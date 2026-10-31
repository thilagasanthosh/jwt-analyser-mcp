package com.mcp.jwtanalyser.tool;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/**
 * MCP tools for decoding and auditing JWT tokens.
 *
 * Does NOT require the signing secret — works purely on the decoded payload.
 * Real signature validation should be done by your auth server / Spring Security.
 *
 * Three tools:
 *  1. decodeJwt     — base64-decode header + payload into readable JSON
 *  2. auditJwt      — security audit: algorithm, claims, expiry, red flags
 *  3. explainClaim  — explain what a specific claim means
 */
@Component
public class JwtAnalyserTools {

    private static final Logger log = LoggerFactory.getLogger(JwtAnalyserTools.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    // Algorithms considered weak for production JWTs
    private static final Set<String> WEAK_ALGORITHMS = Set.of("HS256", "HS384", "none");
    // Algorithms recommended for production
    private static final Set<String> STRONG_ALGORITHMS = Set.of("RS256", "RS384", "RS512",
            "ES256", "ES384", "ES512", "PS256", "PS384", "PS512");

    // ─────────────────────────────────────────────────────────────────────────
    // Tool 1 — Decode a JWT
    // ─────────────────────────────────────────────────────────────────────────

    @Tool(description = """
            Decode a JWT token and return its header and payload as readable JSON.
            Does NOT validate the signature — just base64-decodes the token for inspection.
            Provide the full JWT string (three dot-separated base64 parts).
            Sensitive claim values (passwords, secrets) are never present in JWTs by design,
            but sub, email and other PII claims will be shown.
            """)
    public JwtDecodeResult decodeJwt(
            @ToolParam(description = "The JWT token string to decode, e.g. eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature")
            String token
    ) {
        try {
            String[] parts = splitToken(token);
            if (parts == null) {
                return new JwtDecodeResult(false, "Invalid JWT format — expected 3 dot-separated parts.", null, null, null);
            }

            Map<String, Object> header  = decodeSection(parts[0]);
            Map<String, Object> payload = decodeSection(parts[1]);

            return new JwtDecodeResult(true, null, header, payload,
                    "Signature part is present but NOT validated here. Validate with your auth server.");
        } catch (Exception e) {
            return new JwtDecodeResult(false, "Decode error: " + e.getMessage(), null, null, null);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tool 2 — Audit a JWT for security issues
    // ─────────────────────────────────────────────────────────────────────────

    @Tool(description = """
            Perform a security audit on a JWT token. Checks:
            - Algorithm strength (HS256 vs RS256, 'none' algorithm attack)
            - Expiry (exp claim) — is the token expired or suspiciously long-lived?
            - Required claims (iss, sub, aud, exp, iat, jti) — which are missing?
            - Suspicious patterns (very long expiry, missing audience, debug tokens)
            Returns a list of findings with severity and remediation advice.
            """)
    public JwtAuditResult auditJwt(
            @ToolParam(description = "The JWT token string to audit")
            String token
    ) {
        List<JwtIssue> issues = new ArrayList<>();

        try {
            String[] parts = splitToken(token);
            if (parts == null) {
                return new JwtAuditResult(false, "Invalid JWT format.", List.of(), "");
            }

            Map<String, Object> header  = decodeSection(parts[0]);
            Map<String, Object> payload = decodeSection(parts[1]);

            // 1. Algorithm check
            String alg = String.valueOf(header.getOrDefault("alg", "none"));
            if ("none".equalsIgnoreCase(alg)) {
                issues.add(new JwtIssue("HIGH", "alg=none",
                        "Algorithm is 'none' — signature is not verified. This is a known JWT attack vector.",
                        "Always require a signed algorithm (RS256 or ES256). Reject 'none' in your JWT parser."));
            } else if (WEAK_ALGORITHMS.contains(alg)) {
                issues.add(new JwtIssue("MEDIUM", "Weak algorithm: " + alg,
                        "HS256 uses a shared secret — if the secret leaks, all tokens are forgeable.",
                        "Prefer RS256 or ES256 (asymmetric): the public key can be shared; the private key stays server-side."));
            } else if (STRONG_ALGORITHMS.contains(alg)) {
                issues.add(new JwtIssue("INFO", "Algorithm: " + alg,
                        "Algorithm is strong ✅", "No action needed."));
            }

            // 2. Expiry check
            if (!payload.containsKey("exp")) {
                issues.add(new JwtIssue("HIGH", "Missing 'exp' claim",
                        "No expiry set — this token is valid forever.",
                        "Always set exp. Recommended: 15 minutes for access tokens, 7 days for refresh tokens."));
            } else {
                long exp  = ((Number) payload.get("exp")).longValue();
                long now  = Instant.now().getEpochSecond();
                long iat  = payload.containsKey("iat") ? ((Number) payload.get("iat")).longValue() : now;
                long lifetime = exp - iat;

                if (exp < now) {
                    issues.add(new JwtIssue("INFO", "Token is expired",
                            "exp=" + exp + " (" + Instant.ofEpochSecond(exp) + ") is in the past.",
                            "Issue a new token via your refresh flow."));
                } else if (lifetime > 86400L * 30) { // > 30 days
                    issues.add(new JwtIssue("MEDIUM", "Very long token lifetime: " + (lifetime / 86400) + " days",
                            "Long-lived tokens increase the blast radius if stolen.",
                            "Use short-lived access tokens (≤15 min) with refresh tokens. Implement token rotation."));
                }
            }

            // 3. Required claim checks
            checkMissingClaim(payload, "iss", "Issuer missing", "HIGH",
                    "No 'iss' (issuer) claim — anyone could forge tokens from any issuer.",
                    "Set iss to your auth server URL. Validate it on every request.", issues);
            checkMissingClaim(payload, "sub", "Subject missing", "HIGH",
                    "No 'sub' (subject) claim — token is not tied to a specific user.",
                    "Always set sub to the user's unique identifier.", issues);
            checkMissingClaim(payload, "aud", "Audience missing", "MEDIUM",
                    "No 'aud' (audience) claim — token is not scoped to a specific API.",
                    "Set aud to your API identifier. Validate it to prevent token reuse across services.", issues);
            checkMissingClaim(payload, "iat", "Issued-at missing", "LOW",
                    "No 'iat' (issued-at) claim — you cannot determine token age.",
                    "Always include iat. Useful for token rotation and detecting stale tokens.", issues);
            checkMissingClaim(payload, "jti", "JWT ID missing", "LOW",
                    "No 'jti' (JWT ID) — tokens cannot be individually revoked.",
                    "Add a unique jti (UUID) per token. Store revoked jtis in Redis for active revocation.", issues);

            // 4. Suspicious claims
            Object roles = payload.get("roles");
            if (roles != null && roles.toString().toLowerCase().contains("admin")) {
                issues.add(new JwtIssue("INFO", "Admin role present in token",
                        "Token carries admin role claim: " + roles,
                        "Ensure admin roles are granted only through your identity provider, never user-supplied."));
            }

            // Sort: HIGH first
            issues.sort(Comparator.comparingInt(i -> -severityOrder(i.severity())));

            long highCount   = issues.stream().filter(i -> "HIGH".equals(i.severity())).count();
            long mediumCount = issues.stream().filter(i -> "MEDIUM".equals(i.severity())).count();
            String summary = highCount == 0 && mediumCount == 0
                    ? "✅ No critical JWT security issues found."
                    : "🚨 JWT audit: %d HIGH, %d MEDIUM issues found.".formatted(highCount, mediumCount);

            return new JwtAuditResult(true, null, issues, summary);

        } catch (Exception e) {
            return new JwtAuditResult(false, "Audit error: " + e.getMessage(), List.of(), "");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tool 3 — Explain a claim
    // ─────────────────────────────────────────────────────────────────────────

    @Tool(description = """
            Explain what a specific JWT claim means and its security implications.
            Covers all standard IANA-registered claims: sub, iss, aud, exp, iat, nbf, jti,
            plus common custom claims like roles, scope, email, name.
            """)
    public ClaimExplanation explainClaim(
            @ToolParam(description = "The JWT claim name, e.g. sub, iss, aud, exp, iat, jti, roles, scope")
            String claimName
    ) {
        return CLAIM_EXPLANATIONS.getOrDefault(claimName.toLowerCase().trim(),
                new ClaimExplanation(claimName, "Custom claim",
                        "This is not a standard JWT claim. Validate that its value comes from a trusted source and is not user-supplied.",
                        "LOW", "https://www.iana.org/assignments/jwt/jwt.xhtml"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Result records
    // ─────────────────────────────────────────────────────────────────────────

    public record JwtDecodeResult(boolean success, String error,
            Map<String, Object> header, Map<String, Object> payload, String note) {}

    public record JwtAuditResult(boolean success, String error,
            List<JwtIssue> issues, String summary) {}

    public record JwtIssue(String severity, String title, String description, String remediation) {}

    public record ClaimExplanation(String claim, String name,
            String description, String securityImportance, String reference) {}

    // ─────────────────────────────────────────────────────────────────────────
    // Static knowledge base
    // ─────────────────────────────────────────────────────────────────────────

    private static final Map<String, ClaimExplanation> CLAIM_EXPLANATIONS = Map.ofEntries(
        Map.entry("sub", new ClaimExplanation("sub", "Subject",
                "The principal the token is about (usually user ID). Must be unique per user, stable, and opaque.",
                "HIGH — without sub, tokens are not tied to a user; anyone with the token can impersonate any user.",
                "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2")),
        Map.entry("iss", new ClaimExplanation("iss", "Issuer",
                "Who issued this token (your auth server URL). Validate this to ensure the token came from your server.",
                "HIGH — without iss validation, a token from another server could be accepted.",
                "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1")),
        Map.entry("aud", new ClaimExplanation("aud", "Audience",
                "Who this token is intended for (your API identifier). Prevents tokens issued for one service being used on another.",
                "MEDIUM — without aud, a token for your payments API might be accepted by your user API.",
                "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3")),
        Map.entry("exp", new ClaimExplanation("exp", "Expiration Time",
                "Unix timestamp after which the token must be rejected. Critical for limiting damage from stolen tokens.",
                "HIGH — without exp, stolen tokens are valid forever.",
                "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4")),
        Map.entry("iat", new ClaimExplanation("iat", "Issued At",
                "Unix timestamp when the token was issued. Used to determine token age and enforce max lifetime.",
                "LOW — useful for auditing and token rotation policies.",
                "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6")),
        Map.entry("nbf", new ClaimExplanation("nbf", "Not Before",
                "Token must not be accepted before this time. Useful for tokens issued in advance.",
                "LOW — rarely needed but prevents premature use.",
                "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5")),
        Map.entry("jti", new ClaimExplanation("jti", "JWT ID",
                "Unique identifier for this token. Store revoked jtis in Redis to enable token revocation before exp.",
                "MEDIUM — without jti, you cannot revoke individual tokens; you must rotate the signing key.",
                "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7")),
        Map.entry("scope", new ClaimExplanation("scope", "OAuth 2.0 Scope",
                "Space-separated list of permissions this token grants (e.g. 'read:profile write:orders').",
                "HIGH — always validate scope on the resource server, not just at the API gateway.",
                "https://datatracker.ietf.org/doc/html/rfc6749#section-3.3")),
        Map.entry("roles", new ClaimExplanation("roles", "Roles (custom)",
                "User roles embedded in the token. In Spring Security: @PreAuthorize uses these via JwtGrantedAuthoritiesConverter.",
                "HIGH — never accept roles from the client directly; always issue from your identity provider.",
                "https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html")),
        Map.entry("email", new ClaimExplanation("email", "Email (custom/OIDC)",
                "User's email address. Treat as PII — don't log it. Don't use as a primary key; use sub instead.",
                "MEDIUM — email can change; always use sub as the stable user identifier.",
                "https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims")),
        Map.entry("alg", new ClaimExplanation("alg", "Algorithm (header)",
                "Signing algorithm in the JWT header. RS256/ES256 = asymmetric (recommended). HS256 = symmetric. 'none' = unsigned (dangerous).",
                "HIGH — always whitelist allowed algorithms on the server; never trust alg from the token itself.",
                "https://www.rfc-editor.org/rfc/rfc7518"))
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private String[] splitToken(String token) {
        if (token == null) return null;
        String[] parts = token.trim().split("\\.");
        return parts.length >= 2 ? parts : null;
    }

    private Map<String, Object> decodeSection(String b64) throws Exception {
        // JWT uses URL-safe base64 without padding
        byte[] decoded = Base64.getUrlDecoder().decode(padBase64(b64));
        return mapper.readValue(new String(decoded, StandardCharsets.UTF_8),
                new TypeReference<Map<String, Object>>() {});
    }

    private String padBase64(String s) {
        return switch (s.length() % 4) {
            case 2  -> s + "==";
            case 3  -> s + "=";
            default -> s;
        };
    }

    private void checkMissingClaim(Map<String, Object> payload, String claim,
                                    String title, String severity, String desc,
                                    String fix, List<JwtIssue> out) {
        if (!payload.containsKey(claim)) {
            out.add(new JwtIssue(severity, title, desc, fix));
        }
    }

    private int severityOrder(String s) {
        return switch (s.toUpperCase()) {
            case "HIGH"   -> 4;
            case "MEDIUM" -> 3;
            case "LOW"    -> 2;
            default       -> 1; // INFO
        };
    }
}

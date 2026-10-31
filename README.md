# jwt-analyser-mcp

> MCP server for decoding, auditing, and explaining JSON Web Tokens. Works without the signing secret — just paste the token and get a full security audit.

## Tools

| Tool | Description |
|------|-------------|
| `decodeJwt` | Base64-decode a JWT and display header + payload as readable JSON |
| `auditJwt` | Security audit — algorithm strength, expiry, missing claims, suspicious patterns |
| `explainClaim` | Full explanation of any JWT claim and its security implications |

## Usage with Claude

### HTTP mode (Claude Code)
```bash
mvn spring-boot:run
```

### Stdio mode (Claude Desktop)
```bash
mvn spring-boot:run --spring.profiles.active=stdio
```

## Example Conversations

### Decode a token
> "Decode this JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature"

```json
Header:  { "alg": "HS256", "typ": "JWT" }
Payload: { "sub": "user123" }
Note: Signature present but NOT validated here. Validate with your auth server.
```

### Audit a token
> "Audit this JWT for security issues: <token>"

```
🚨 JWT Audit: 2 HIGH, 1 MEDIUM issues

🔴 HIGH   — Missing 'exp' claim
           No expiry set — this token is valid forever.
           Fix: Always set exp. Recommended: 15 minutes for access tokens.

🔴 HIGH   — Missing 'iss' claim
           No issuer claim — anyone could forge tokens from any issuer.
           Fix: Set iss to your auth server URL. Validate it on every request.

🟠 MEDIUM — Weak algorithm: HS256
           HS256 uses a shared secret — if the secret leaks, all tokens are forgeable.
           Fix: Prefer RS256 or ES256 (asymmetric keys).
```

### Understand a claim
> "What does the 'aud' claim do in a JWT?"

```
Audience (aud)
Who this token is intended for (your API identifier).
Prevents tokens issued for one service being used on another.

Security importance: MEDIUM
Without aud, a token for your payments API might be accepted by your user API.

Reference: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
```

## Security Checks

### Algorithm Audit

| Algorithm | Status | Notes |
|-----------|--------|-------|
| `none` | 🔴 HIGH | Known attack vector — never accept |
| `HS256` / `HS384` | 🟠 MEDIUM | Shared secret — prefer asymmetric |
| `RS256` / `ES256` etc. | ✅ OK | Asymmetric — recommended |

### Claim Checks

| Claim | Missing = | Why |
|-------|-----------|-----|
| `exp` | 🔴 HIGH | Token valid forever if absent |
| `iss` | 🔴 HIGH | Cannot verify token came from your server |
| `sub` | 🔴 HIGH | Token not tied to a specific user |
| `aud` | 🟠 MEDIUM | Token usable across services |
| `iat` | 🟡 LOW | Cannot determine token age |
| `jti` | 🟡 LOW | Cannot revoke individual tokens |

### Expiry Checks

- Token expired → reported as INFO
- Token lifetime > 30 days → 🟠 MEDIUM warning
- No `exp` claim → 🔴 HIGH

## Claims Reference

| Claim | Name | Description |
|-------|------|-------------|
| `sub` | Subject | User identifier (use this, not email, as primary key) |
| `iss` | Issuer | Auth server URL — validate this on every request |
| `aud` | Audience | API identifier — prevents token reuse across services |
| `exp` | Expiration | Unix timestamp — token invalid after this |
| `iat` | Issued At | When token was issued |
| `nbf` | Not Before | Token not valid before this time |
| `jti` | JWT ID | Unique ID — enables individual token revocation |
| `scope` | Scope | OAuth 2.0 permissions (e.g. `read:profile`) |
| `roles` | Roles | User roles — validate these come from your IDP |
| `email` | Email | PII — don't use as primary key, use `sub` |
| `alg` | Algorithm | In header — always whitelist allowed algorithms server-side |

## Spring Boot JWT Integration

### Validate JWT with Spring Security

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt
                .decoder(jwtDecoder())
                .jwtAuthenticationConverter(jwtAuthConverter())
            )
        );
    return http.build();
}

@Bean
public JwtDecoder jwtDecoder() {
    // RS256 — public key from your auth server's JWKS endpoint
    return NimbusJwtDecoder.withJwkSetUri("https://auth.yourapp.com/.well-known/jwks.json")
        .build();
}
```

### Use claims in controllers

```java
@GetMapping("/profile")
public UserProfile getProfile(JwtAuthenticationToken auth) {
    String userId = auth.getToken().getSubject(); // sub claim
    List<String> roles = auth.getToken().getClaimAsStringList("roles");
    // Never trust userId from request body — always use the token
    return userService.findById(userId);
}
```

## Requirements

- Java 21+
- Maven 3.9+
- Spring Boot 3.5.0
- Spring AI 1.0.0 MCP Server
- Jackson Databind (included transitively)

## Build

```bash
mvn clean package
java -jar target/jwt-analyser-mcp-0.0.1-SNAPSHOT.jar
```

## Docker

```bash
docker build -t jwt-analyser-mcp .
docker run -p 8080:8080 jwt-analyser-mcp
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "jwt-analyser": {
      "command": "java",
      "args": [
        "-jar",
        "/path/to/jwt-analyser-mcp-0.0.1-SNAPSHOT.jar",
        "--spring.profiles.active=stdio"
      ]
    }
  }
}
```

## Security Note

This tool **does not validate JWT signatures**. It only decodes the base64-encoded header and payload sections. Always validate token signatures in your application using Spring Security's JWT support or a proper JWKS endpoint. Use this tool for debugging and auditing, not for trust decisions.

## Related Projects

- [secret-scanner-mcp](../secret-scanner-mcp) — Detect secrets and credentials in source code
- [owasp-checker-mcp](../owasp-checker-mcp) — OWASP Top 10 AST analysis for Spring Boot
- [http-security-headers-mcp](../http-security-headers-mcp) — HTTP security header analysis
- [dependency-vuln-mcp](../dependency-vuln-mcp) — CVE scanning via OSV.dev
- [test-coverage-gap-mcp](../test-coverage-gap-mcp) — Find untested Spring Boot code

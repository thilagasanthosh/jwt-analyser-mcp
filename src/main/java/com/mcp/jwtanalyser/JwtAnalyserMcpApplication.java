package com.mcp.jwtanalyser;

import com.mcp.jwtanalyser.tool.JwtAnalyserTools;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * JWT Analyser MCP Server
 *
 * Exposes MCP tools to Claude for auditing JSON Web Tokens:
 *   - decodeJwt      : decode header + payload (no signature validation needed)
 *   - auditJwt       : security audit — algorithm, claims, expiry, suspicious patterns
 *   - explainClaim   : explain what a JWT claim means and its security implications
 */
@SpringBootApplication
public class JwtAnalyserMcpApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtAnalyserMcpApplication.class, args);
    }

    @Bean
    public ToolCallbackProvider jwtToolProvider(JwtAnalyserTools tools) {
        return MethodToolCallbackProvider.builder().toolObjects(tools).build();
    }
}

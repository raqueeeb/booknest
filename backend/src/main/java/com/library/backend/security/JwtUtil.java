package com.library.backend.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

/**
 * Issues and verifies the API's access tokens.
 *
 * <p>Two properties of this class matter for security:
 *
 * <ul>
 *   <li><b>No role claim.</b> The token carries only the subject, the user id and
 *       the token version. Authorities are read from the database on every
 *       request (see {@link JwtAuthenticationFilter}), so a tampered token cannot
 *       grant a role the account does not have.
 *   <li><b>Verification is delegated to a maintained library</b> (JJWT), which
 *       compares signatures in constant time, rejects an unexpected algorithm
 *       rather than trusting the token's own header, and parses claims properly.
 * </ul>
 *
 * <p>The signing key comes from {@code app.jwt.secret} and has no default: the
 * application refuses to start without one. The value is never logged.
 */
@Component
public class JwtUtil {

    /** HS256 keys must be at least 256 bits; a shorter secret is rejected at startup. */
    private static final int MIN_SECRET_BYTES = 32;

    public static final String CLAIM_USER_ID = "uid";
    public static final String CLAIM_TOKEN_VERSION = "tv";

    private final SecretKey key;
    private final long expirationMs;

    public JwtUtil(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.expiration-ms}") long expirationMs) {

        byte[] keyBytes = secret == null ? new byte[0] : secret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < MIN_SECRET_BYTES) {
            // The secret itself is never included in the message.
            throw new IllegalStateException(
                    "app.jwt.secret must be at least " + MIN_SECRET_BYTES
                            + " bytes for HS256; the configured value is too short. "
                            + "Set the JWT_SECRET environment variable to a long random string.");
        }
        if (expirationMs <= 0) {
            throw new IllegalStateException("app.jwt.expiration-ms must be greater than zero");
        }
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.expirationMs = expirationMs;
    }

    /**
     * @param tokenVersion the account's current token version; a password change
     *                     increments it, which invalidates every token issued before.
     */
    public String generateToken(String username, Long userId, int tokenVersion) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(username)
                .claim(CLAIM_USER_ID, userId)
                .claim(CLAIM_TOKEN_VERSION, tokenVersion)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(expirationMs)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Verifies the signature, the algorithm, the expiry and the required claims.
     *
     * @throws JwtException if the token is malformed, unsigned, signed with another
     *                      key or algorithm, expired, or missing a required claim
     */
    public JwtClaims validateToken(String token) {
        Jws<Claims> jws = Jwts.parser()
                .verifyWith(key)
                // Only HS256 is accepted, whatever the token's own header says.
                .sig().add(Jwts.SIG.HS256).and()
                .build()
                .parseSignedClaims(token);

        if (!Jwts.SIG.HS256.getId().equals(jws.getHeader().getAlgorithm())) {
            throw new JwtException("Unexpected token algorithm");
        }

        Claims claims = jws.getPayload();
        String subject = claims.getSubject();
        Long userId = claims.get(CLAIM_USER_ID, Number.class) == null
                ? null
                : claims.get(CLAIM_USER_ID, Number.class).longValue();
        Integer tokenVersion = claims.get(CLAIM_TOKEN_VERSION, Number.class) == null
                ? null
                : claims.get(CLAIM_TOKEN_VERSION, Number.class).intValue();

        if (subject == null || subject.isBlank() || userId == null || tokenVersion == null
                || claims.getExpiration() == null) {
            throw new JwtException("Token is missing a required claim");
        }

        return new JwtClaims(subject, userId, tokenVersion);
    }

    /** The verified claims this application relies on. Deliberately carries no role. */
    public static class JwtClaims {

        private final String username;
        private final Long userId;
        private final int tokenVersion;

        public JwtClaims(String username, Long userId, int tokenVersion) {
            this.username = username;
            this.userId = userId;
            this.tokenVersion = tokenVersion;
        }

        public String getUsername() {
            return username;
        }

        public Long getUserId() {
            return userId;
        }

        public int getTokenVersion() {
            return tokenVersion;
        }
    }
}

package com.library.backend.security;

import com.library.backend.model.Student;
import com.library.backend.repository.StudentRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Authenticates a request from its bearer token.
 *
 * <p>The token establishes <em>which account</em> is calling and nothing more.
 * The account itself is then loaded by its immutable id, and the authorities
 * come from the role stored in the database. A token cannot therefore carry a
 * role at all, let alone an elevated one, and a role change takes effect on the
 * very next request rather than when the token happens to expire.
 *
 * <p>A token is rejected when the account no longer exists, or when the
 * account's token version has moved on, which is how a password change
 * invalidates tokens issued before it.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final StudentRepository studentRepository;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, StudentRepository studentRepository) {
        this.jwtUtil = jwtUtil;
        this.studentRepository = studentRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                JwtUtil.JwtClaims claims = jwtUtil.validateToken(token);

                // The database, not the token, decides who this is and what they may do.
                Optional<Student> account = studentRepository.findById(claims.getUserId());
                if (account.isEmpty()) {
                    // Deleted account: the token is worthless even if still unexpired.
                    SecurityContextHolder.clearContext();
                    filterChain.doFilter(request, response);
                    return;
                }

                Student student = account.get();
                if (student.currentTokenVersion() != claims.getTokenVersion()) {
                    // Issued before the last password change.
                    SecurityContextHolder.clearContext();
                    filterChain.doFilter(request, response);
                    return;
                }

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        student.getUsername(),
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_" + student.getRole().name()))
                );
                authentication.setDetails(student.getId());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception ex) {
                // Malformed, expired, or signed with another key: stay anonymous.
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }
}

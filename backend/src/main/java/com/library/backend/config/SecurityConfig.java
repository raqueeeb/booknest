package com.library.backend.config;

import com.library.backend.security.JwtAuthenticationFilter;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final List<String> allowedOrigins;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          @Value("${app.cors.allowed-origins}") List<String> allowedOrigins) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.allowedOrigins = allowedOrigins;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .headers(headers -> 
                headers.frameOptions(frame -> frame.sameOrigin())
            )
            .authorizeHttpRequests(auth -> auth

                // Allow frontend login/register
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/students/register",
                    "/api/students/login",
                    "/students/register",
                    "/students/login"
                ).permitAll()

                // Public book browsing
                .requestMatchers(HttpMethod.GET, "/api/books/**").permitAll()

                // Allow browser preflight requests
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()


                // Admin routes
                .requestMatchers(HttpMethod.POST, "/api/books/**")
                    .hasRole("ADMIN")

                .requestMatchers(HttpMethod.PUT, "/api/books/**")
                    .hasRole("ADMIN")

                .requestMatchers(HttpMethod.DELETE, "/api/books/**")
                    .hasRole("ADMIN")

                .requestMatchers(HttpMethod.GET, "/api/students")
                    .hasRole("ADMIN")

                .requestMatchers(HttpMethod.DELETE, "/api/students/**")
                    .hasRole("ADMIN")

                .requestMatchers(HttpMethod.GET, "/api/borrow")
                    .hasRole("ADMIN")

                .requestMatchers(HttpMethod.GET, "/api/borrow/active")
                    .hasRole("ADMIN")

                .requestMatchers(HttpMethod.PUT, "/api/borrow/return/**")
                    .hasRole("ADMIN")

                .requestMatchers("/api/admin/**")
                    .hasRole("ADMIN")


                // Everything else requires login
                .anyRequest().authenticated()
            )
            // Tell the two failure modes apart: 401 means "no usable token"
            // (missing, expired, tampered with, or belonging to a deleted account),
            // 403 means "signed in, but not allowed to do this". Without this the
            // container answered 403 to both, which hides an expired session.
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((request, response, authException) ->
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication required"))
                .accessDeniedHandler((request, response, deniedException) ->
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied"))
            )
            .addFilterBefore(
                jwtAuthenticationFilter,
                UsernamePasswordAuthenticationFilter.class
            );

        return http.build();
    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();

        // Exact origins only, from configuration. The previous wildcard over every
        // *.vercel.app site let any project hosted there call this API with
        // credentials allowed.
        configuration.setAllowedOrigins(allowedOrigins);

        configuration.setAllowedMethods(
            List.of(
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
                "OPTIONS"
            )
        );

        configuration.setAllowedHeaders(List.of("*"));

        configuration.setAllowCredentials(true);


        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
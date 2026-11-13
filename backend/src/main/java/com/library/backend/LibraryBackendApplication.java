package com.library.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;

/**
 * Authentication here is stateless and bearer-token based: every request is
 * resolved by {@code JwtAuthenticationFilter} against the database. There is no
 * form login and no HTTP Basic, so Spring Boot's fallback in-memory user is not
 * only unused but actively unhelpful, because creating it prints a generated
 * password to the application log on every startup. Excluding its
 * auto-configuration removes both the account and the log line.
 */
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
public class LibraryBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(LibraryBackendApplication.class, args);
	}

}

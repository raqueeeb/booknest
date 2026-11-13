package com.library.backend.config;

import com.library.backend.model.Role;
import com.library.backend.model.Student;
import com.library.backend.repository.StudentRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * A deliberate, operator-initiated reset of an administrator's password, for the
 * case where nobody can sign in to change it the normal way.
 *
 * <p>It is off unless {@code ADMIN_PASSWORD_RESET} names the administrator to
 * reset. Naming the account rather than using a flag makes the intent explicit
 * and stops a stray "true" somewhere from rewriting a password by accident.
 * {@code ADMIN_PASSWORD} supplies the new value, which is typed into the hosting
 * dashboard's own field and never appears in the repository or in a log line.
 *
 * <p>Applying it is safe to repeat: when the stored password already matches, it
 * does nothing, so a restart with the variables still set neither re-hashes the
 * password nor signs anyone out. It does, however, keep the door open, so the
 * runner asks loudly for both variables to be removed once the reset is done.
 *
 * <p>Only an existing ADMIN account is ever touched. A username that does not
 * exist, or that belongs to a student, is refused: this is a reset, never a way
 * to create or promote an administrator.
 */
@Component
@Order(100) // after DataSeeder, so a first-run admin exists before this considers it
public class AdminPasswordReset implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminPasswordReset.class);

    private final StudentRepository studentRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${ADMIN_PASSWORD_RESET:}")
    private String resetUsername;

    @Value("${ADMIN_PASSWORD:}")
    private String newPassword;

    public AdminPasswordReset(StudentRepository studentRepository, PasswordEncoder passwordEncoder) {
        this.studentRepository = studentRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (resetUsername == null || resetUsername.isBlank()) {
            return; // the normal case: the feature is dormant
        }

        if (newPassword == null || newPassword.isBlank()) {
            log.error("ADMIN_PASSWORD_RESET is set but ADMIN_PASSWORD is empty, so no password was changed. "
                    + "Set both, or remove ADMIN_PASSWORD_RESET.");
            return;
        }

        Optional<Student> found = studentRepository.findByUsername(resetUsername.trim());
        if (found.isEmpty()) {
            log.error("ADMIN_PASSWORD_RESET names an account that does not exist. Nothing was changed.");
            return;
        }

        Student account = found.get();
        if (account.getRole() != Role.ADMIN) {
            log.error("ADMIN_PASSWORD_RESET names an account that is not an administrator. "
                    + "Nothing was changed and no account was promoted.");
            return;
        }

        if (passwordEncoder.matches(newPassword, account.getPassword())) {
            log.warn("Administrator password reset requested, but the password is already the configured one, "
                    + "so nothing was changed. REMOVE ADMIN_PASSWORD_RESET and ADMIN_PASSWORD from the environment.");
            return;
        }

        account.setPassword(passwordEncoder.encode(newPassword));
        // Anyone holding a token for this account is signed out.
        account.invalidateIssuedTokens();
        studentRepository.save(account);

        log.warn("Administrator password was reset from configuration, and existing sessions were ended. "
                + "REMOVE ADMIN_PASSWORD_RESET and ADMIN_PASSWORD from the environment now: while they remain set, "
                + "a later restart would undo a password changed inside the application.");
    }
}

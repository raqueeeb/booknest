package com.library.backend.config;

import com.library.backend.model.Role;
import com.library.backend.model.Student;
import com.library.backend.repository.StudentRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Creates the first administrator, once.
 *
 * <p>The previous version re-encoded the configured password and forced the ADMIN
 * role on every startup. That undid password changes made in the application, and
 * it meant that pointing {@code ADMIN_USERNAME} at an existing student's username
 * silently promoted that student. Both are fixed here:
 *
 * <ul>
 *   <li>if any administrator already exists, nothing is touched;
 *   <li>an account that already exists under the configured username is never
 *       promoted, only reported;
 *   <li>an administrator is created only when there is none and both settings are
 *       present, so the operation is safe to repeat.
 * </ul>
 *
 * <p>The settings are optional: an instance that already has an administrator
 * starts without them. Neither has a default, so no credential is ever baked in.
 */
@Component
public class DataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);

    private final StudentRepository studentRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${ADMIN_USERNAME:}")
    private String adminUsername;

    @Value("${ADMIN_PASSWORD:}")
    private String adminPassword;

    public DataSeeder(StudentRepository studentRepository, PasswordEncoder passwordEncoder) {
        this.studentRepository = studentRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (studentRepository.existsByRole(Role.ADMIN)) {
            log.info("An administrator already exists; leaving it untouched.");
            return;
        }

        if (adminUsername == null || adminUsername.isBlank()
                || adminPassword == null || adminPassword.isBlank()) {
            log.warn("No administrator exists and ADMIN_USERNAME/ADMIN_PASSWORD are not set, "
                    + "so none was created. Set both and restart to create the first administrator.");
            return;
        }

        Optional<Student> existing = studentRepository.findByUsername(adminUsername);
        if (existing.isPresent()) {
            // Promoting here would hand administrator rights to whoever holds that
            // account, which is exactly the accident this guard exists to prevent.
            log.error("ADMIN_USERNAME matches an existing account that is not an administrator. "
                    + "No account was promoted and no password was changed. "
                    + "Choose a username that is not already taken.");
            return;
        }

        Student admin = new Student();
        admin.setFullName("Library Admin");
        admin.setUsername(adminUsername);
        admin.setEmail("admin@library.system");
        admin.setPassword(passwordEncoder.encode(adminPassword));
        admin.setRole(Role.ADMIN);
        admin.setTokenVersion(0);
        studentRepository.save(admin);

        log.info("Created the initial administrator account.");
    }
}

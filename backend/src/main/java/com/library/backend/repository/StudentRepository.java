package com.library.backend.repository;

import com.library.backend.model.Role;
import com.library.backend.model.Student;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface StudentRepository extends JpaRepository<Student, Long> {

    Optional<Student> findByUsername(String username);

    Optional<Student> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    /** Used by the seeder to decide whether an administrator already exists. */
    boolean existsByRole(Role role);
}

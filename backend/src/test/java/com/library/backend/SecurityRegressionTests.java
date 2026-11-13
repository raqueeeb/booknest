package com.library.backend;

import com.library.backend.config.AdminPasswordReset;
import com.library.backend.config.DataSeeder;
import com.library.backend.model.Role;
import com.library.backend.model.Student;
import com.library.backend.repository.StudentRepository;
import com.library.backend.security.JwtUtil;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Regression tests for the authorization rules this application depends on.
 *
 * <p>They run against an in-memory database (see src/test/resources), so no
 * production credential is needed and no production data is touched.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityRegressionTests {

    private static final String TEST_SIGNING_KEY =
            "test-only-signing-key-not-used-anywhere-else-abcdefghij";

    @Autowired private MockMvc mvc;
    @Autowired private StudentRepository students;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private JwtUtil jwtUtil;
    private final ObjectMapper json = new ObjectMapper();

    @BeforeEach
    void clearAccounts() {
        students.deleteAll();
    }

    // ---------------------------------------------------------------- helpers

    private String register(String username, String password) throws Exception {
        String body = json.writeValueAsString(Map.of(
                "fullName", "Test Person",
                "username", username,
                "email", username + "@example.test",
                "password", password));
        String response = mvc.perform(post("/api/students/register")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(response).get("token").asText();
    }

    private Student makeAdmin(String username, String password) {
        Student admin = new Student();
        admin.setFullName("Admin Person");
        admin.setUsername(username);
        admin.setEmail(username + "@example.test");
        admin.setPassword(passwordEncoder.encode(password));
        admin.setRole(Role.ADMIN);
        return students.save(admin);
    }

    private String tokenFor(Student s) {
        return jwtUtil.generateToken(s.getUsername(), s.getId(), s.currentTokenVersion());
    }

    /** An attacker-built token: correctly signed, but claiming whatever it likes. */
    private String forgedToken(Map<String, Object> claims, String subject) {
        SecretKey key = Keys.hmacShaKeyFor(TEST_SIGNING_KEY.getBytes(StandardCharsets.UTF_8));
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(subject)
                .claims(claims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(3600)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    // ---------------------------------------------------------------- 1 & 2

    @Test
    @DisplayName("1+2: registration always creates a STUDENT, and cannot create an ADMIN")
    void registrationAlwaysCreatesStudent() throws Exception {
        // The request even asks for ADMIN; the field does not exist on the DTO and
        // the service hard-codes the role.
        String body = json.writeValueAsString(Map.of(
                "fullName", "Sneaky Person",
                "username", "sneaky",
                "email", "sneaky@example.test",
                "password", "password123",
                "role", "ADMIN"));
        mvc.perform(post("/api/students/register")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("STUDENT"));

        assertThat(students.findByUsername("sneaky").orElseThrow().getRole()).isEqualTo(Role.STUDENT);
    }

    // ---------------------------------------------------------------- 3

    @Test
    @DisplayName("3: a token claiming ADMIN does not grant admin access")
    void forgedRoleClaimIsIgnored() throws Exception {
        register("plainstudent", "password123");
        Student student = students.findByUsername("plainstudent").orElseThrow();

        // Correctly signed with the real key, and claiming the admin role.
        String forged = forgedToken(
                Map.of("uid", student.getId(), "tv", student.currentTokenVersion(),
                        "role", "ADMIN", "authorities", "ROLE_ADMIN"),
                student.getUsername());

        mvc.perform(get("/api/students").header("Authorization", "Bearer " + forged))
                .andExpect(status().isForbidden());
    }

    // ---------------------------------------------------------------- 4 & 5

    @Test
    @DisplayName("4: a student cannot reach an admin endpoint")
    void studentCannotReachAdminEndpoint() throws Exception {
        String token = register("student1", "password123");
        mvc.perform(get("/api/admin/statistics").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/students").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("5: a genuine admin can reach admin endpoints")
    void adminCanReachAdminEndpoints() throws Exception {
        Student admin = makeAdmin("admin1", "password123");
        mvc.perform(get("/api/students").header("Authorization", "Bearer " + tokenFor(admin)))
                .andExpect(status().isOk());
    }

    // ---------------------------------------------------------------- 6

    @Test
    @DisplayName("6: a role change takes effect on the next request, with the same token")
    void roleChangeAppliesImmediately() throws Exception {
        String token = register("promoted", "password123");
        mvc.perform(get("/api/students").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());

        Student s = students.findByUsername("promoted").orElseThrow();
        s.setRole(Role.ADMIN);
        students.save(s);

        // Same token, new authority: the role comes from the database, not the token.
        mvc.perform(get("/api/students").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        s.setRole(Role.STUDENT);
        students.save(s);

        // And a demotion is just as immediate.
        mvc.perform(get("/api/students").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    // ---------------------------------------------------------------- 7

    @Test
    @DisplayName("7: a deleted user's token is rejected")
    void deletedUserTokenIsRejected() throws Exception {
        String token = register("goner", "password123");
        Student s = students.findByUsername("goner").orElseThrow();
        Long id = s.getId();

        mvc.perform(get("/api/students/" + id).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        students.deleteById(id);

        mvc.perform(get("/api/students/" + id).header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    // ---------------------------------------------------------------- 8

    @Test
    @DisplayName("8: changing the password invalidates tokens issued before it")
    void passwordChangeInvalidatesOldTokens() throws Exception {
        String oldToken = register("rotator", "password123");
        Student s = students.findByUsername("rotator").orElseThrow();

        String body = json.writeValueAsString(Map.of(
                "currentPassword", "password123",
                "newPassword", "brand-new-password"));
        mvc.perform(put("/api/students/" + s.getId())
                        .header("Authorization", "Bearer " + oldToken)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());

        mvc.perform(get("/api/students/" + s.getId()).header("Authorization", "Bearer " + oldToken))
                .andExpect(status().isUnauthorized());

        // A token issued after the change works again.
        Student after = students.findById(s.getId()).orElseThrow();
        mvc.perform(get("/api/students/" + after.getId())
                        .header("Authorization", "Bearer " + tokenFor(after)))
                .andExpect(status().isOk());
    }

    // ---------------------------------------------------------------- 9

    @Test
    @DisplayName("9: expired, malformed and wrongly signed tokens are all rejected")
    void badTokensAreRejected() throws Exception {
        register("victim", "password123");
        Student s = students.findByUsername("victim").orElseThrow();
        String path = "/api/students/" + s.getId();

        // Expired.
        SecretKey key = Keys.hmacShaKeyFor(TEST_SIGNING_KEY.getBytes(StandardCharsets.UTF_8));
        String expired = Jwts.builder().subject(s.getUsername())
                .claim("uid", s.getId()).claim("tv", 0)
                .issuedAt(Date.from(Instant.now().minusSeconds(7200)))
                .expiration(Date.from(Instant.now().minusSeconds(3600)))
                .signWith(key, Jwts.SIG.HS256).compact();
        mvc.perform(get(path).header("Authorization", "Bearer " + expired))
                .andExpect(status().isUnauthorized());

        // Malformed.
        mvc.perform(get(path).header("Authorization", "Bearer not.a.token"))
                .andExpect(status().isUnauthorized());

        // Signed with a different key of valid length.
        SecretKey other = Keys.hmacShaKeyFor(
                "a-completely-different-signing-key-for-tests-only".getBytes(StandardCharsets.UTF_8));
        String wrongKey = Jwts.builder().subject(s.getUsername())
                .claim("uid", s.getId()).claim("tv", 0)
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(other, Jwts.SIG.HS256).compact();
        mvc.perform(get(path).header("Authorization", "Bearer " + wrongKey))
                .andExpect(status().isUnauthorized());

        // Unsigned ("alg": "none") is rejected rather than trusted.
        String unsigned = Jwts.builder().subject(s.getUsername())
                .claim("uid", s.getId()).claim("tv", 0)
                .expiration(Date.from(Instant.now().plusSeconds(3600))).compact();
        mvc.perform(get(path).header("Authorization", "Bearer " + unsigned))
                .andExpect(status().isUnauthorized());

        // Missing the required uid claim.
        String noUid = Jwts.builder().subject(s.getUsername()).claim("tv", 0)
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(key, Jwts.SIG.HS256).compact();
        mvc.perform(get(path).header("Authorization", "Bearer " + noUid))
                .andExpect(status().isUnauthorized());
    }

    // ---------------------------------------------------------------- 10 & 11

    @Test
    @DisplayName("10: seeding does not overwrite an existing admin's password")
    void seederDoesNotOverwriteAdminPassword() {
        Student admin = makeAdmin("existingadmin", "original-password");
        String storedHash = admin.getPassword();

        runSeeder("existingadmin", "a-different-password");

        Student after = students.findByUsername("existingadmin").orElseThrow();
        assertThat(after.getPassword()).isEqualTo(storedHash);
        assertThat(passwordEncoder.matches("original-password", after.getPassword())).isTrue();
    }

    @Test
    @DisplayName("11: seeding never promotes an existing student")
    void seederDoesNotPromoteStudent() throws Exception {
        register("ordinary", "password123");

        // The seeder is pointed straight at that student's username.
        runSeeder("ordinary", "password123");

        assertThat(students.findByUsername("ordinary").orElseThrow().getRole())
                .isEqualTo(Role.STUDENT);
    }

    // ------------------------------------------------- emergency admin reset

    @Test
    @DisplayName("reset: changes an administrator's password and ends existing sessions")
    void emergencyResetChangesAdminPassword() throws Exception {
        Student admin = makeAdmin("resetme", "forgotten-password");
        String oldToken = tokenFor(admin);
        mvc.perform(get("/api/students").header("Authorization", "Bearer " + oldToken))
                .andExpect(status().isOk());

        runReset("resetme", "a-fresh-password");

        Student after = students.findByUsername("resetme").orElseThrow();
        assertThat(passwordEncoder.matches("a-fresh-password", after.getPassword())).isTrue();
        assertThat(after.getRole()).isEqualTo(Role.ADMIN);

        // The old session is over.
        mvc.perform(get("/api/students").header("Authorization", "Bearer " + oldToken))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/students").header("Authorization", "Bearer " + tokenFor(after)))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("reset: repeating it changes nothing and does not sign anyone out")
    void emergencyResetIsIdempotent() throws Exception {
        Student admin = makeAdmin("steady", "original-password");
        runReset("steady", "new-password");

        Student afterFirst = students.findByUsername("steady").orElseThrow();
        String hashAfterFirst = afterFirst.getPassword();
        int versionAfterFirst = afterFirst.currentTokenVersion();
        String token = tokenFor(afterFirst);

        runReset("steady", "new-password");

        Student afterSecond = students.findByUsername("steady").orElseThrow();
        assertThat(afterSecond.getPassword()).isEqualTo(hashAfterFirst);
        assertThat(afterSecond.currentTokenVersion()).isEqualTo(versionAfterFirst);
        mvc.perform(get("/api/students").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("reset: refuses a student account, and is dormant unless asked for")
    void emergencyResetRefusesNonAdmins() throws Exception {
        register("justastudent", "password123");
        String hashBefore = students.findByUsername("justastudent").orElseThrow().getPassword();

        runReset("justastudent", "attempted-takeover");

        Student after = students.findByUsername("justastudent").orElseThrow();
        assertThat(after.getRole()).isEqualTo(Role.STUDENT);
        assertThat(after.getPassword()).isEqualTo(hashBefore);

        // Unknown account: nothing is created.
        runReset("nobody-at-all", "irrelevant");
        assertThat(students.findByUsername("nobody-at-all")).isEmpty();

        // Dormant when no username is configured.
        Student admin = makeAdmin("untouched", "keep-this-password");
        runReset("", "would-have-changed-it");
        assertThat(students.findById(admin.getId()).orElseThrow().getPassword())
                .isEqualTo(admin.getPassword());
    }

    private void runReset(String username, String password) {
        AdminPasswordReset reset = new AdminPasswordReset(students, passwordEncoder);
        ReflectionTestUtils.setField(reset, "resetUsername", username);
        ReflectionTestUtils.setField(reset, "newPassword", password);
        reset.run();
    }

    @Test
    @DisplayName("10b: seeding creates the first admin, and is safe to repeat")
    void seederCreatesFirstAdminIdempotently() {
        runSeeder("firstadmin", "password123");
        Student created = students.findByUsername("firstadmin").orElseThrow();
        assertThat(created.getRole()).isEqualTo(Role.ADMIN);

        runSeeder("firstadmin", "yet-another-password");
        Student after = students.findByUsername("firstadmin").orElseThrow();
        assertThat(after.getPassword()).isEqualTo(created.getPassword());
        assertThat(students.count()).isEqualTo(1);
    }

    private void runSeeder(String username, String password) {
        DataSeeder seeder = new DataSeeder(students, passwordEncoder);
        ReflectionTestUtils.setField(seeder, "adminUsername", username);
        ReflectionTestUtils.setField(seeder, "adminPassword", password);
        seeder.run();
    }

    // ---------------------------------------------------------------- 12

    @Test
    @DisplayName("12: a user cannot read or modify another user's record")
    void ownershipIsEnforced() throws Exception {
        String tokenA = register("usera", "password123");
        register("userb", "password123");
        Student b = students.findByUsername("userb").orElseThrow();

        mvc.perform(get("/api/students/" + b.getId()).header("Authorization", "Bearer " + tokenA))
                .andExpect(status().isForbidden());

        String body = json.writeValueAsString(Map.of("fullName", "Renamed By Someone Else"));
        mvc.perform(put("/api/students/" + b.getId())
                        .header("Authorization", "Bearer " + tokenA)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());

        // Deleting someone else's account is an admin-only route.
        mvc.perform(delete("/api/students/" + b.getId()).header("Authorization", "Bearer " + tokenA))
                .andExpect(status().isForbidden());

        assertThat(students.findById(b.getId())).isPresent();
    }

    @Test
    @DisplayName("12b: an identity change requires the current password, and hashes are never returned")
    void identityChangesRequireCurrentPassword() throws Exception {
        String token = register("changer", "password123");
        Student s = students.findByUsername("changer").orElseThrow();

        String withoutPassword = json.writeValueAsString(Map.of("email", "new@example.test"));
        mvc.perform(put("/api/students/" + s.getId())
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON).content(withoutPassword))
                .andExpect(status().isBadRequest());

        String withPassword = json.writeValueAsString(Map.of(
                "email", "new@example.test", "currentPassword", "password123"));
        String response = mvc.perform(put("/api/students/" + s.getId())
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON).content(withPassword))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(response).doesNotContain("password");
        assertThat(response).doesNotContain("$2a$");
    }

    // ---------------------------------------------------------------- 13

    @Test
    @DisplayName("13: shipped configuration carries no hard-coded credential")
    void configurationHasNoHardCodedCredentials() throws Exception {
        for (String name : new String[]{"application.properties", "application-mysql.properties"}) {
            Path file = Path.of("src/main/resources", name);
            assertThat(file).exists();
            for (String line : Files.readAllLines(file)) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
                if (!trimmed.matches("(?i).*(password|username|secret|url)\\s*=.*")) continue;
                String value = trimmed.substring(trimmed.indexOf('=') + 1).trim();
                // Every credential-bearing value must be an environment reference
                // with no fallback after a colon.
                assertThat(value)
                        .as("%s -> %s must come from the environment with no default",
                                name, trimmed.split("=")[0])
                        .matches("\\$\\{[A-Za-z0-9_.]+\\}");
            }
        }
    }

    // ---------------------------------------------------------------- 14

    @Test
    @DisplayName("14: CORS allows the configured origin and refuses anything else")
    void corsRejectsUnknownOrigins() throws Exception {
        mvc.perform(options("/api/books")
                        .header("Origin", "https://booknestx.vercel.app")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk());

        // A different site on the same shared host must not be allowed.
        mvc.perform(options("/api/books")
                        .header("Origin", "https://someone-elses-project.vercel.app")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden());

        mvc.perform(options("/api/books")
                        .header("Origin", "https://evil.example")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden());
    }

    // ---------------------------------------------------------------- extra

    @Test
    @DisplayName("public book browsing stays open, and anonymous writes stay closed")
    void publicEndpointsBehave() throws Exception {
        mvc.perform(get("/api/books")).andExpect(status().isOk());
        mvc.perform(post("/api/books").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());
    }
}

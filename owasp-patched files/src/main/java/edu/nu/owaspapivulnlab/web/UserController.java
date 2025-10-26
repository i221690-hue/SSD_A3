package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.model.CreateUserReq;
import edu.nu.owaspapivulnlab.model.UserDTO;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    private final PasswordEncoder encoder;

    public UserController(AppUserRepository users, PasswordEncoder encoder) {
        this.users = users;
        this.encoder = encoder;
    }

    private UserDTO toDto(AppUser u) {
        return UserDTO.builder().id(u.getId()).username(u.getUsername()).email(u.getEmail()).build();
    }

    @GetMapping
    public List<UserDTO> list() {
        return users.findAll().stream().map(this::toDto).collect(Collectors.toList());
    }

    @PostMapping
    public UserDTO create(@Valid @RequestBody CreateUserReq body) {
        AppUser u = AppUser.builder()
                .username(body.getUsername())
                .password(encoder.encode(body.getPassword()))
                .email(body.getEmail())
                .role("USER")
                .isAdmin(false)
                .build();
        AppUser saved = users.save(u);
        return toDto(saved);
    }

    // Only allow deletion by admin or the user themself
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id, Authentication auth) {
        String current = auth == null ? null : auth.getName();
        AppUser target = users.findById(id).orElse(null);
        if (target == null) {
            return ResponseEntity.notFound().build();
        }
        AppUser currentUser = current == null ? null : users.findByUsername(current).orElse(null);
        boolean allowed = false;
        if (currentUser != null) {
            if (currentUser.isAdmin() || currentUser.getId().equals(target.getId())) {
                allowed = true;
            }
        }
        if (!allowed) {
            Map<String, String> err = new HashMap<>();
            err.put("error", "forbidden");
            return ResponseEntity.status(403).body(err);
        }
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
}

package com.testingsecurityexplainer.controller;

import com.testingsecurityexplainer.dto.RegisterRequest;
import com.testingsecurityexplainer.dto.UserResponse;
import com.testingsecurityexplainer.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public registration endpoints — no authentication required.
 *
 * <p>Two variants:
 * <ul>
 *   <li>{@code POST /register} — creates a standard USER account</li>
 *   <li>{@code POST /register/admin} — creates an ADMIN account (for manual testing convenience)</li>
 * </ul>
 * All business logic lives in {@link UserService}.
 */
@RestController
@RequestMapping("/register")
public class RegistrationController {

    private final UserService userService;

    public RegistrationController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping
    public ResponseEntity<UserResponse> registerUser(@Valid @RequestBody RegisterRequest request) {
        UserResponse created = userService.registerUser(request.getUsername(), request.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PostMapping("/admin")
    public ResponseEntity<UserResponse> registerAdmin(@Valid @RequestBody RegisterRequest request) {
        UserResponse created = userService.registerAdmin(request.getUsername(), request.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }
}


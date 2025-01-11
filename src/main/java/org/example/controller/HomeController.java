package org.example.controller;

import lombok.Data;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class HomeController {

    @GetMapping("/home")
    public ResponseEntity<?> getDashboard(Authentication authentication) {
        String username = authentication.getName(); // Retrieved from JWT

        String message = "Welcome, " + username + "!";

        return ResponseEntity.ok(new ApiResponse(message));
    }

    @Data
    private static class ApiResponse {
        private String message;

        public ApiResponse(String message) {
            this.message = message;
        }
    }
}

package org.example.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.*;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {
    @Autowired
    private AuthTokenFilter authTokenFilter;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    // Define password encoder bean
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Configure security filter chain
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF as we're using JWT
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/h2-console/**") // Disable CSRF for H2 console
                )

                // Set session management to stateless
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Set permissions on endpoints
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll() // Public endpoints
                        .requestMatchers("/h2-console/**").permitAll() // Allow H2 console
                        .anyRequest().authenticated() // Secure all other endpoints
                )

                // Allow frames from the same origin to support H2 console
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions
                                .sameOrigin()
                        )
                );

        // Add JWT token filter before UsernamePasswordAuthenticationFilter
        http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}

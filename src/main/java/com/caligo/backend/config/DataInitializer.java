package com.caligo.backend.config;

import com.caligo.backend.user.Role;
import com.caligo.backend.user.User;
import com.caligo.backend.user.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataInitializer {

    @Bean
    ApplicationRunner bootstrapAdmin(
            UserRepository users,
            PasswordEncoder passwordEncoder,
            @Value("${caligo.bootstrap.admin.username}") String username,
            @Value("${caligo.bootstrap.admin.email}") String email,
            @Value("${caligo.bootstrap.admin.password}") String password
    ) {
        return args -> {
            if (users.count() == 0) {
                users.save(new User(username, email, passwordEncoder.encode(password), Role.ADMIN));
            }
        };
    }
}


package com.caligo.backend.auth.dto;

import com.caligo.backend.user.Role;
import com.caligo.backend.user.User;

import java.util.UUID;

public record UserProfile(
        UUID id,
        String username,
        String email,
        Role role
) {

    public static UserProfile from(User user) {
        return new UserProfile(user.getId(), user.getUsername(), user.getEmail(), user.getRole());
    }
}


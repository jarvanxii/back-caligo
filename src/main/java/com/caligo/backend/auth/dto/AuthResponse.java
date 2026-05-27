package com.caligo.backend.auth.dto;

import com.caligo.backend.user.User;

public record AuthResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        UserProfile user
) {

    public static AuthResponse bearer(String accessToken, long expiresIn, User user) {
        return new AuthResponse(accessToken, "Bearer", expiresIn, UserProfile.from(user));
    }
}


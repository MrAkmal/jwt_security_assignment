package com.example.jwt_security.utils;

import com.auth0.jwt.algorithms.Algorithm;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

public class JWTUtils {


    public static String secretKey = "jbvnafdvbn@#fgd12454_41841dfashidhs%&cpoasc";

    public static Date getExpiresAt() {
        return Date.from(LocalDateTime.now().plusMinutes(5).toInstant(ZoneOffset.UTC));
    }


    public static Algorithm getAlgorithm() {
        return Algorithm.HMAC256(secretKey);
    }

}

package com.example.jwt_security.service;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.jwt_security.dto.ResetPasswordDTO;
import com.example.jwt_security.dto.SessionDTO;
import com.example.jwt_security.entity.User;
import com.example.jwt_security.repository.UserRepository;
import com.example.jwt_security.utils.JWTUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.MimeTypeUtils;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Service
public class AuthService implements UserDetailsService {

    private final UserRepository repository;
    private final ObjectMapper objectMapper;
    private  final PasswordEncoder passwordEncoder;

    @Autowired
    public AuthService(UserRepository repository, ObjectMapper objectMapper, PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.objectMapper = objectMapper;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = repository.findByUsername(username);


        if (Objects.isNull(user)) throw new RuntimeException("User not found");

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(user.getAuthorities())
                .build();

    }


    @SneakyThrows
    public SessionDTO refreshToken(HttpServletRequest request, HttpServletResponse response) {

        String authorizationHeader = request.getHeader(AUTHORIZATION);
        System.out.println("authorizationHeader = " + authorizationHeader);

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {

            String refreshToken = authorizationHeader.substring("Bearer ".length());

            JWTVerifier verifier = JWT.require(JWTUtils.getAlgorithm()).build();
            DecodedJWT decodedJWT = verifier.verify(refreshToken);
            String username = decodedJWT.getSubject();

            User user = repository.findByUsername(username);


            String accessToken = JWT.create()
                    .withSubject(user.getUsername())
                    .withExpiresAt(JWTUtils.getExpiresAt())
                    .withClaim("roles", user.getAuthority())
                    .withIssuer(request.getRequestURI())
                    .sign(JWTUtils.getAlgorithm());


            Map<String, String> tokens = new HashMap<>();

            tokens.put("accessToken", accessToken);
            tokens.put("refreshToken", refreshToken);
            response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
            objectMapper.writeValue(response.getOutputStream(), tokens);


            return new SessionDTO(accessToken, refreshToken);
        }

        throw new RuntimeException("access denied");

    }

    @Transactional
    public void resetPassword(ResetPasswordDTO dto,String token) {


        JWTVerifier verifier = JWT.require(Algorithm.HMAC256("dasdasdasdijo12489&*()!@casdkf_+/*-")).build();

        DecodedJWT decodedJWT = verifier.verify(token);

        if (decodedJWT.getExpiresAt().before(Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC))) || !Objects.equals(dto.getPassword(), dto.getConfirmPassword())) throw new RuntimeException("Token expired");


        String username = decodedJWT.getSubject();
        String email = decodedJWT.getClaim("email").asString();

        User user = repository.findByUsername(username);

        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        if (!user.getEmail().equals(email)) throw new RuntimeException("Token not valid");

        repository.update(user);

    }


    public String sendCode(String userName) {

        System.out.println("userName = " + userName);

        User user = repository.findByUsername(userName);

        String sender = "security@gmail.com";
        String receiver = user.getEmail();

//        String code = generateCode();
        String code = generateLink(user);

        String username = "822ec6bba4a0d8"; // generated by Mailtrap
        String password = "324045c07236cf"; // generated by Mailtrap
        String host = "smtp.mailtrap.io";
        String port = "2525";

        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");//it’s optional in Mailtrap
        props.put("mail.smtp.host", host);
        props.put("mail.smtp.port", port);

        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });


        try {
            Message message = new MimeMessage(session);

            message.setFrom(new InternetAddress(sender));

            message.addRecipient(Message.RecipientType.TO, new InternetAddress(receiver));

            message.setSubject("Code for reset password");
            message.setText(code);

            Transport.send(message);

        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }

        return code;
    }


    private String generateCode() {

        int max = 999_999;
        int min = 100_000;
        int randomNumber = (int) Math.floor(Math.random() * (max - min + 1) + min);

        return String.valueOf(randomNumber);
    }


    private String generateLink(User user) {
        String token = JWT.create()
                .withSubject(user.getUsername())
                .withClaim("email", user.getEmail())
                .withExpiresAt(Date.from(LocalDateTime.now().plusMinutes(2).toInstant(ZoneOffset.UTC)))
                .sign(Algorithm.HMAC256("dasdasdasdijo12489&*()!@casdkf_+/*-"));

        return "http://localhost:8080/reset-password?token=" + token;
    }

}

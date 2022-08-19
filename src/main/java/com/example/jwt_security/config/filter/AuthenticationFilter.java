package com.example.jwt_security.config.filter;

import com.auth0.jwt.JWT;
import com.example.jwt_security.dto.DataDTO;
import com.example.jwt_security.dto.ErrorDTO;
import com.example.jwt_security.dto.LoginDto;
import com.example.jwt_security.dto.SessionDTO;
import com.example.jwt_security.utils.JWTUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    private final AuthenticationManager authenticationManager;
    private final ObjectMapper mapper;


    public AuthenticationFilter(AuthenticationManager authenticationManager, ObjectMapper mapper) {
        super.setFilterProcessesUrl("/login");
        this.authenticationManager = authenticationManager;
        this.mapper = mapper;
    }


    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        LoginDto loginDto = mapper.readValue(request.getReader(), LoginDto.class);
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());
        return authenticationManager.authenticate(token);


    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        org.springframework.security.core.userdetails.User user = (org.springframework.security.core.userdetails.User) authResult.getPrincipal();

        List<String> authorities = user.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();


        String accessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(JWTUtils.getExpiresAt())
                .withClaim("roles", authorities)
                .withIssuer(request.getRequestURI())
                .sign(JWTUtils.getAlgorithm());


        String refreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(Date.from(JWTUtils.getExpiresAt().toInstant().plus(10, ChronoUnit.MINUTES)))
                .withIssuer(request.getRequestURI())
                .sign(JWTUtils.getAlgorithm());


        LocalDateTime accessExpiresAt = LocalDateTime.ofInstant(JWTUtils.getExpiresAt().toInstant(), ZoneId.systemDefault());
        LocalDateTime refreshExpiresAt = LocalDateTime.ofInstant(JWTUtils.getExpiresAt().toInstant().plus(10, ChronoUnit.MINUTES), ZoneId.systemDefault());

        DataDTO<SessionDTO> sessionDTO = new DataDTO<>(new SessionDTO(accessToken, accessExpiresAt, refreshToken, refreshExpiresAt));

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        mapper.writeValue(response.getOutputStream(), sessionDTO);

    }


    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        DataDTO<ErrorDTO> dto = new DataDTO<>(new ErrorDTO(LocalDateTime.now(), failed.getMessage()));
        mapper.writeValue(response.getOutputStream(), dto);

    }
}

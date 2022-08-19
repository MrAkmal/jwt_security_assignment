package com.example.jwt_security.controller;

import com.example.jwt_security.dto.ResetPasswordDTO;
import com.example.jwt_security.dto.SessionDTO;
import com.example.jwt_security.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
public class SecurityController {


    private final AuthService service;


    @Autowired
    public SecurityController(AuthService service) {
        this.service = service;
    }


    @GetMapping("/refresh-token")
    public SessionDTO refreshToken(HttpServletRequest request, HttpServletResponse response) {
        return service.refreshToken(request, response);
    }


    @PostMapping("/reset-password")
    public Boolean resetPassword(@RequestBody ResetPasswordDTO dto, @RequestParam("token") String token) {
        service.resetPassword(dto,token);
        return true;
    }

    @PostMapping("/send-code")
    public String sendCode(@RequestBody String username) {
        return service.sendCode(username);
    }


    @GetMapping("/authorize")
    public Boolean authorizeRequest() {
        return true;
    }




    @GetMapping("/login/oauth2/code/google")
    public String googleOauth2(OAuth2AuthenticationToken token){
        System.out.println("token.getPrincipal() = " + token.getPrincipal());

        return "With google";
    }


    @GetMapping("/login/oauth2/code/github")
    public String githubOauth2(OAuth2AuthenticationToken token){
        System.out.println("token.getPrincipal() = " + token.getPrincipal());

        return "With github";
    }


    @GetMapping("/")
    public String home(){
        return "home";
    }

}

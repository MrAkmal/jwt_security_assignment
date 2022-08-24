package com.example.jwt_security.config;

import com.example.jwt_security.config.filter.AuthenticationFilter;
import com.example.jwt_security.config.filter.AuthorizationFilter;
import com.example.jwt_security.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableGlobalMethodSecurity(
        jsr250Enabled = true,
        securedEnabled = true,
        prePostEnabled = true
)
@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {

    private final AuthService service;
    private final ObjectMapper mapper;
    private final PasswordEncoder passwordEncoder;

    public SecurityConfigurer(AuthService service, ObjectMapper mapper, PasswordEncoder passwordEncoder) {
        this.service = service;
        this.mapper = mapper;
        this.passwordEncoder = passwordEncoder;
    }


//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//
//        return http.authorizeRequests()
//                .anyRequest().authenticated()
//                .and()
//                .addFilter(new AuthenticationFilter(authenticationManager(), mapper))
//                .build();
//
//    }

    // deprecated Spring Security 5.7

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManager(), mapper);

        authenticationFilter.setFilterProcessesUrl("/login");


//        http.oauth2Login();

        http.csrf().disable().cors().disable()
                .authorizeRequests()
                .antMatchers("/login", "/refresh-token", "/reset-password", "/send-code").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilter(authenticationFilter)
                .addFilterBefore(new AuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(service).passwordEncoder(passwordEncoder);
    }


//    @Bean
//    public UserDetailsManager users() {
//        UserDetails user = User.builder()
//                .passwordEncoder()
//                .build();
//        JdbcUserDetailsManager users = new JdbcUserDetailsManager();
//        users.createUser(user);
//        return users;
//    }


    // deprecated Spring Security 5.7

//    @Bean
//    @Override
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

}

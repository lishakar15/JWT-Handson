package com.jwt.JWT.Handson.configuration;

import com.jwt.JWT.Handson.MyUserDetailsService;
import com.jwt.JWT.Handson.jwt.AuthenticationExceptionHandler;
import com.jwt.JWT.Handson.jwt.JwtRequestFilter;
import jakarta.servlet.Filter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfigurer {
    @Autowired
    MyUserDetailsService myUserDetailsService;
    @Autowired
    JwtRequestFilter jwtRequestFilter;
    @Autowired
    AuthenticationExceptionHandler authenticationExceptionHandler;



    @Bean
    public SecurityFilterChain configureSecurityFilterChain(HttpSecurity https) throws Exception {
        https.authorizeHttpRequests((request->request.requestMatchers("/home").permitAll()))
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/authenticate-user").permitAll()
                        .requestMatchers("/home").permitAll()
                        .anyRequest().authenticated()
                )
                .userDetailsService(myUserDetailsService)
                .httpBasic(Customizer.withDefaults())
                .exceptionHandling(exception -> exception.authenticationEntryPoint(authenticationExceptionHandler))
                .sessionManagement(session ->session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS));
        https.csrf(csrf -> csrf.disable());
        https.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
        return https.build();
    }

    @Bean
    public PasswordEncoder getPasswordEncoder()
    {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }

}

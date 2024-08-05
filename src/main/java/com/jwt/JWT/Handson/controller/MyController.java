package com.jwt.JWT.Handson.controller;

import com.jwt.JWT.Handson.jwt.JwtUtils;
import com.jwt.JWT.Handson.model.LoginRequest;
import com.jwt.JWT.Handson.model.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class MyController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtils jwtUtils;
    @GetMapping("/home")
    public String homePage()
    {
        return "Welcome to Home Page";
    }
    @PostMapping("/authenticate-user")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest)
    {
        Authentication authentication;
        try
        {
            authentication =
                    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUserName()
                            ,loginRequest.getPassword()));
        }
        catch(AuthenticationException ex)
        {
            Map<String,Object> map = new HashMap<>();
            map.put("message","Bad Credentials");
            map.put("status",false);
            return new ResponseEntity<>(map, HttpStatus.NOT_FOUND);
        }
        //Authentication Completed, Set the Authentication object into the Spring Context for future requests
        SecurityContextHolder.getContext().setAuthentication(authentication);
        //Authentication Successfully Completed Let's generate the JWT Token
        UserDetails userDetails = (UserDetails) authentication.getPrincipal(); //Principal -> Authenticated User
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);
        LoginResponse loginResponse = LoginResponse.builder()
                .jwtToken(jwtToken)
                .userName(userDetails.getUsername())
                .build();
        return new ResponseEntity<>(loginResponse,HttpStatus.OK);
    }

    @GetMapping("/admin")
    public String adminPage()
    {
        return "Hi Admin";
    }
}

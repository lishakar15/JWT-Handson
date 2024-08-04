package com.jwt.JWT.Handson;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyController {
    @GetMapping("/home")
    public String homePage()
    {
        return "Welcome to Home Page";
    }

    @GetMapping("/admin")
    public String adminPage()
    {
        return "Hi Admin";
    }
}

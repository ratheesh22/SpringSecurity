package com.cognizant.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
public class SecurityController {



    private JwtEncoder jwtEncoder;
    public  SecurityController(final  JwtEncoder jwtEncoder){
        this.jwtEncoder=jwtEncoder;
    }

    @PostMapping("/post")
    public String postSomething(@RequestParam("str") String str){


     return str;
    }

    @PostMapping("/authenticate")
    public JWTResponse jwtResponse(Authentication authentication){
        return new JWTResponse(createToken(authentication));
    }

    private String createToken(Authentication authentication) {
        JwtClaimsSet claimsSet=JwtClaimsSet.builder()
                .issuer("rateesh")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60*20)).build();

        JwtEncoderParameters parameters=JwtEncoderParameters.from(claimsSet);
        return jwtEncoder.encode(parameters).getTokenValue();
    }


    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @PostMapping("/auth")
    public Authentication hello1(Authentication authentication){
        return authentication;
    }


}
record JWTResponse(String token) {

}


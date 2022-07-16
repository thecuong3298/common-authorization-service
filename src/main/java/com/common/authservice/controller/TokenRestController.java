package com.common.authservice.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/oauth/token")
@RequiredArgsConstructor
@SuppressWarnings("deprecation")
@CrossOrigin(originPatterns = "*", allowedHeaders = "*", allowCredentials = "true",
        exposedHeaders = {HttpHeaders.SET_COOKIE})
public class TokenRestController {

    private final ConsumerTokenServices tokenServices;

    @DeleteMapping("/revoke/{tokenId:.*}")
    public ResponseEntity<Void> revokeToken(@PathVariable("tokenId") String tokenId) {
        boolean isTokenExisted = this.tokenServices.revokeToken(tokenId);
        if (isTokenExisted) {
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }
}

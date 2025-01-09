package com.bivektor.samples.spring.security.oauth2;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

  @PreAuthorize("isAuthenticated()")
  @GetMapping("/")
  public ResponseEntity<String> index(Authentication authentication) {
    var result = "You are logged in with name: " + authentication.getName();
    return ResponseEntity.ok(result);
  }
}

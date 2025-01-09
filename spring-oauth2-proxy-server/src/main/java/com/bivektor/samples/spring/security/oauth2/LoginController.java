package com.bivektor.samples.spring.security.oauth2;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

  @GetMapping("/login")
  public ResponseEntity<?> login() {
    // Returning not found for security purposes. You can implement your own login page
    // but be warned that end users of applications which login through this proxy
    // may end up there.
    return ResponseEntity.notFound().build();
  }
}

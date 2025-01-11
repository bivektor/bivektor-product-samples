package com.bivektor.samples.spring.security.oauth2.config;

import com.bivektor.spring.security.oauth2.proxy.config.ProxyOAuth2AuthorizationServerConfigurerCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class OAuth2AuthorizationServerConfig {

  @Bean
  @Order(0)
  public SecurityFilterChain authorizationServerSecurityFilterChain(
      HttpSecurity http,
      ProxyOAuth2AuthorizationServerConfigurerCustomizer customizer
  ) throws Exception {

    var authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

    http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher());

    http.with(authorizationServerConfigurer, server -> {
      // Enable OpenID Connect 1.0
      server.oidc(Customizer.withDefaults());
      server.tokenEndpoint(customizer::configureTokenEndpoint);
    });

    http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

    // Unauthenticated requests return a basic JSON response. Customize this based on your needs
    http.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(
        (request, response, authException) -> {
          response.setStatus(HttpStatus.UNAUTHORIZED.value());
          response.setContentType(MediaType.APPLICATION_JSON_VALUE);

          String error = "unauthorized";
          String errorDescription = "Full authentication is required";

          String jsonResponse = String.format(
              "{\"error\":\"%s\",\"error_description\":\"%s\"}",
              error,
              errorDescription
          );

          response.getWriter().write(jsonResponse);
        }
    ));

    return http.build();
  }
}

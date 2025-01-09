package com.bivektor.samples.spring.security.oauth2.config;

import com.bivektor.security.oauth2.server.proxy.DelegatingProxyOAuth2AuthorizationService;
import com.bivektor.security.oauth2.server.proxy.ProxyAuthorizationManager;
import com.bivektor.security.oauth2.server.proxy.ProxyOAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class OAuth2AuthorizationServerConfig {

  @Bean
  public DelegatingProxyOAuth2AuthorizationService oAuth2AuthorizationService(
      ProxyAuthorizationManager proxyAuthorizationManager
  ) {
    // Change the default authorization service if you want to store authorization data in a different place
    var defaultAuthorizationService = new InMemoryOAuth2AuthorizationService();

    return DelegatingProxyOAuth2AuthorizationService.of(
        defaultAuthorizationService,
        proxyAuthorizationManager
    );
  }

  @Bean
  @Order(0)
  public SecurityFilterChain authorizationServerSecurityFilterChain(
      HttpSecurity http,
      ProxyAuthorizationManager proxyAuthorizationManager,
      OAuth2AuthorizationService oAuth2AuthorizationService
  ) throws Exception {

    var authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

    http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher());

    http.with(authorizationServerConfigurer, server -> {
      server.oidc(Customizer.withDefaults());
      server.tokenEndpoint(endpoint -> endpoint.authenticationProviders(providers -> {
        var proxyAuthorizationCodeAuthenticationManager =
            new ProxyOAuth2AuthorizationCodeAuthenticationProvider(
                oAuth2AuthorizationService, proxyAuthorizationManager
            );

        // Add proxy authorization manager before Spring's default OAuth2AuthorizationCodeAuthenticationProvider
        providers.add(0, proxyAuthorizationCodeAuthenticationManager);
      }));
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

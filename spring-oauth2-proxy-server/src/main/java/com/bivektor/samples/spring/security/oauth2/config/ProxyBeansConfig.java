package com.bivektor.samples.spring.security.oauth2.config;

import com.bivektor.security.oauth2.server.proxy.DefaultProxyAuthorizationManager;
import com.bivektor.security.oauth2.server.proxy.DelegatingProxyOAuth2AuthorizationService;
import com.bivektor.security.oauth2.server.proxy.ProxyAuthorizationManager;
import com.bivektor.security.oauth2.server.proxy.ProxyLoginAccessValidator;
import org.jetbrains.annotations.NotNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Configuration(proxyBeanMethods = false)
public class ProxyBeansConfig {

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
  public DefaultProxyAuthorizationManager proxyAuthorizationManager(
      RegisteredClientRepository registeredClientRepository,
      AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository
  ) {
    var result = new DefaultProxyAuthorizationManager(
        registeredClientRepository,
        authorizationRequestRepository
    );

    // Login access validator checks if a registered client is allowed to log in via a specific login client
    // For demo purposes, we skip that validation. Uncomment to use default validator
    result.setLoginAccessValidator(ProxyLoginAccessValidator.NULL_VALIDATOR);

    return result;
  }
}

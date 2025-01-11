package com.bivektor.samples.spring.security.oauth2.config;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

import com.bivektor.spring.security.oauth2.proxy.DefaultProxyAuthorizationManager;
import com.bivektor.spring.security.oauth2.proxy.ProxyAuthenticationFailureHandler;
import com.bivektor.spring.security.oauth2.proxy.ProxyAuthenticationSuccessHandler;
import com.bivektor.spring.security.oauth2.proxy.ProxyAuthorizationManager;
import com.bivektor.spring.security.oauth2.proxy.ProxyOAuth2AuthorizationRequestRepository;
import com.bivektor.spring.security.oauth2.proxy.ProxyOAuth2AuthorizationRequestResolver;
import com.bivektor.spring.security.oauth2.proxy.config.ProxyBeansConfiguration;
import com.bivektor.spring.security.oauth2.proxy.config.ProxyOAuth2LoginPostProcessor;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Import(ProxyBeansConfiguration.class)
public class DefaultSecurityConfiguration {

  private static final String LOGIN_PAGE = "/login";

  @Bean
  public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
    return new NimbusJwtEncoder(jwkSource);
  }

  @Bean
  public InMemoryOAuth2AuthorizationService oAuth2AuthorizationService() {
    return new InMemoryOAuth2AuthorizationService();
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
    // For demo purposes, we skip that validation. Comment this line to use default validator
    result.setLoginAccessValidator((proxyClient, authorizationRequest) -> {});

    return result;
  }

  @Bean
  public ProxyOAuth2AuthorizationRequestRepository oauth2AuthorizationRequestRepository() {
    return ProxyOAuth2AuthorizationRequestRepository.ofHttpSession();
  }

  @Bean
  public ProxyOAuth2AuthorizationRequestResolver oAuth2AuthorizationRequestResolver(
      ClientRegistrationRepository clientRegistrationRepository,
      ProxyAuthorizationManager proxyAuthorizationManager
  ) {
    var defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(
        clientRegistrationRepository,
        DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
    );

    var result = new ProxyOAuth2AuthorizationRequestResolver(
        defaultResolver,
        proxyAuthorizationManager
    );

    // Set this value as false to force OAuth2 login to work only for proxy requests.
    result.setNonProxyRequestsAllowed(true);

    return result;
  }

  @Bean
  public ProxyAuthenticationSuccessHandler proxyAuthenticationSuccessHandler(
      ProxyAuthorizationManager proxyAuthorizationManager,
      OAuth2AuthorizationService oAuth2AuthorizationService,
      OAuth2AuthorizedClientRepository authorizedClientRepository
  ) {
    return new ProxyAuthenticationSuccessHandler(
        proxyAuthorizationManager,
        oAuth2AuthorizationService,
        authorizedClientRepository
    );
  }

  @Bean
  public ProxyAuthenticationFailureHandler proxyAuthenticationFailureHandler(
      ProxyAuthorizationManager proxyAuthorizationManager
  ) {
    return new ProxyAuthenticationFailureHandler(proxyAuthorizationManager, LOGIN_PAGE + "?error");
  }

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(
      HttpSecurity http,
      ProxyAuthenticationSuccessHandler oauth2LoginSuccessHandler,
      ProxyAuthenticationFailureHandler oauth2LoginFailureHandler,
      OAuth2AuthorizationRequestResolver authorizationRequestResolver
  ) throws Exception {
    http.authorizeHttpRequests(authorize ->
        authorize
            .requestMatchers("/oauth2/token/**", "/error", LOGIN_PAGE).permitAll()
            .anyRequest().authenticated()
    );

    http.oauth2Login(login -> {
      login.withObjectPostProcessor(new ProxyOAuth2LoginPostProcessor());

      // Use a custom login page, because we don't want the default login page to list
      // all possible clients to end users of the applications that use us as a proxy
      // You may consider protecting login page by IP address or other means so that only known
      // users access it
      login.loginPage(LOGIN_PAGE);
      login.successHandler(oauth2LoginSuccessHandler);
      login.failureHandler(oauth2LoginFailureHandler);

      login.authorizationEndpoint(endpoint -> {
        endpoint.baseUri(DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        endpoint.authorizationRequestResolver(authorizationRequestResolver);
        endpoint.authorizationRequestRepository(oauth2AuthorizationRequestRepository());
      });
    });

    return http.build();
  }
}

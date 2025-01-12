package com.bivektor.samples.spring.security.oauth2.config;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

import com.bivektor.spring.security.oauth2.proxy.ProxyAuthorizationManager;
import com.bivektor.spring.security.oauth2.proxy.ProxyAuthorizationRequestRepository;
import com.bivektor.spring.security.oauth2.proxy.ProxyLoginResultAuthorizer;
import com.bivektor.spring.security.oauth2.proxy.ProxyRequestLoader;
import com.bivektor.spring.security.oauth2.proxy.client.ProxyAuthenticationFailureHandler;
import com.bivektor.spring.security.oauth2.proxy.client.ProxyAuthenticationSuccessHandler;
import com.bivektor.spring.security.oauth2.proxy.client.ProxyOAuth2AuthorizationRequestResolver;
import com.bivektor.spring.security.oauth2.proxy.client.validation.CompositeProxyRequestValidator;
import com.bivektor.spring.security.oauth2.proxy.client.validation.RedirectUriProxyRequestValidator;
import com.bivektor.spring.security.oauth2.proxy.config.ProxyBeansConfiguration;
import com.bivektor.spring.security.oauth2.proxy.config.ProxyOAuth2LoginPostProcessor;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Import(ProxyBeansConfiguration.class) // This import is necessary until we have a more flexible configuration logic
public class DefaultSecurityConfiguration {

  private static final String LOGIN_PAGE = "/login";

  // JwtEncoder bean is required for proxy components
  @Bean
  public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
    return new NimbusJwtEncoder(jwkSource);
  }

  @Bean
  public ProxyAuthorizationRequestRepository oauth2AuthorizationRequestRepository() {
    // Store OAuth2AuthorizationRequest objects in Http session
    return ProxyAuthorizationRequestRepository.ofHttpSession();
  }

  @Bean
  public ProxyOAuth2AuthorizationRequestResolver oAuth2AuthorizationRequestResolver(
      ClientRegistrationRepository clientRegistrationRepository,
      RegisteredClientRepository registeredClientRepository
  ) {

    var defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(
        clientRegistrationRepository,
        DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
    );

    var result = new ProxyOAuth2AuthorizationRequestResolver(defaultResolver, registeredClientRepository);

    // Set this value as false to force OAuth2 login to work only for proxy requests.
    result.setNonProxyRequestsAllowed(true);

    // For demo purposes, setting a custom validator to keep only the redirect uri validation but
    // skip allowed clients validation which validates if the proxying client has proxy login access
    // to a specific login client. Uncomment this to use default validator
    result.setProxyRequestValidator(new CompositeProxyRequestValidator(
        List.of(new RedirectUriProxyRequestValidator())
    ));

    return result;
  }

  @Bean
  public ProxyAuthenticationSuccessHandler proxyAuthenticationSuccessHandler(
      ProxyLoginResultAuthorizer loginResultAuthorizer,
      ProxyRequestLoader proxyRequestLoader,
      OAuth2AuthorizedClientRepository authorizedClientRepository
  ) {
    return new ProxyAuthenticationSuccessHandler(
        proxyRequestLoader,
        loginResultAuthorizer,
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

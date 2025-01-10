package com.bivektor.samples.spring.security.oauth2.config;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

import com.bivektor.security.oauth2.server.proxy.ProxyAuthenticationFailureHandler;
import com.bivektor.security.oauth2.server.proxy.ProxyAuthenticationSuccessHandler;
import com.bivektor.security.oauth2.server.proxy.ProxyAuthorizationManager;
import com.bivektor.security.oauth2.server.proxy.ProxyOAuth2AuthorizationRequestRepository;
import com.bivektor.security.oauth2.server.proxy.ProxyOAuth2AuthorizationRequestResolver;
import com.bivektor.security.oauth2.server.proxy.config.ProxyOAuth2LoginPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class OAuth2ClientConfig {

  private static final String LOGIN_PAGE = "/login";


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
  public SecurityFilterChain oauth2ClientSecurityFilterChain(
      HttpSecurity http,
      ProxyAuthenticationSuccessHandler oauth2LoginSuccessHandler,
      ProxyAuthenticationFailureHandler oauth2LoginFailureHandler,
      OAuth2AuthorizationRequestResolver authorizationRequestResolver
  ) throws Exception {
    http.authorizeHttpRequests(authorize ->
        authorize
            .requestMatchers("/oauth2/token/**", "/login").permitAll()
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

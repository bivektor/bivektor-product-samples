package com.bivektor.samples.spring.security.oauth2.config;

import com.bivektor.security.oauth2.server.proxy.DefaultProxyOAuth2UserService;
import com.bivektor.security.oauth2.server.proxy.ProxyAccessTokenResponseClient;
import com.bivektor.security.oauth2.server.proxy.ProxyAuthenticationSuccessHandler;
import com.bivektor.security.oauth2.server.proxy.ProxyAuthorizationManager;
import com.bivektor.security.oauth2.server.proxy.ProxyOAuth2AuthorizationRequestResolver;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
public class OAuth2ClientConfig {

  private static final String AUTHORIZATION_ENDPOINT_BASE_URL = "/oauth2/authorization";

  @Bean
  public DefaultProxyOAuth2UserService oAuth2UserService() {
    return new DefaultProxyOAuth2UserService(new DefaultOAuth2UserService());
  }

  @Bean
  public OidcUserService oidcUserService() {
    var oidcUserService = new OidcUserService();
    oidcUserService.setOauth2UserService(oAuth2UserService());
    return oidcUserService;
  }

  @Bean
  public ProxyOAuth2AuthorizationRequestResolver oAuth2AuthorizationRequestResolver(
      ClientRegistrationRepository clientRegistrationRepository,
      ProxyAuthorizationManager proxyAuthorizationManager,
      ApplicationEventPublisher applicationEventPublisher
  ) {
    var defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(
        clientRegistrationRepository,
        AUTHORIZATION_ENDPOINT_BASE_URL
    );

    return new ProxyOAuth2AuthorizationRequestResolver(
        defaultResolver,
        proxyAuthorizationManager,
        applicationEventPublisher
    );
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
  @Order(2)
  public SecurityFilterChain oauth2ClientSecurityFilterChain(
      HttpSecurity http,
      @Qualifier("proxyAuthenticationSuccessHandler")
      AuthenticationSuccessHandler proxyAuthenticationSuccessHandler,
      OAuth2AuthorizationRequestResolver authorizationRequestResolver,
      OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService,
      OidcUserService oidcUserService
  ) throws Exception {
    http.authorizeHttpRequests(authorize ->
        authorize
            .requestMatchers("/oauth2/token/**", "/login").permitAll()
            .anyRequest().authenticated()
    );

    http.oauth2Login(login -> {

      // Use a custom login page, because we don't want the default login page to list
      // all possible clients to end users of the applications that use us as a proxy
      // You may consider protecting login page by IP address or other means so that only known
      // users access it
      login.loginPage("/login");

      login.successHandler(proxyAuthenticationSuccessHandler);

      login.authorizationEndpoint(endpoint -> {
        endpoint.baseUri(AUTHORIZATION_ENDPOINT_BASE_URL);
        endpoint.authorizationRequestResolver(authorizationRequestResolver);
      });

      login.tokenEndpoint(endpoint ->
          endpoint.accessTokenResponseClient(new ProxyAccessTokenResponseClient())
      );

      login.userInfoEndpoint(endpoint -> {
        endpoint.userService(oAuth2UserService);
        endpoint.oidcUserService(oidcUserService);
      });
    });

    return http.build();
  }
}

package com.bivektor.samples.spring.security.oauth2.config;

import com.bivektor.security.oauth2.server.proxy.DelegatingProxyOAuth2AuthorizationService;
import com.bivektor.security.oauth2.server.proxy.ProxyAuthorizationManager;
import com.bivektor.security.oauth2.server.proxy.ProxyOAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration(proxyBeanMethods = false)
public class OAuth2AuthorizationServerConfig {

  @Bean
  public DelegatingProxyOAuth2AuthorizationService oAuth2AuthorizationService(
      ProxyAuthorizationManager proxyAuthorizationManager
  ) {
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

    http.exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
        new LoginUrlAuthenticationEntryPoint("/login"),
        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
    ));

    return http.build();
  }
}

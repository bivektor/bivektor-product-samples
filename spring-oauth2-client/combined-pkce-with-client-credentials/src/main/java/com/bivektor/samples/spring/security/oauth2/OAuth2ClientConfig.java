package com.bivektor.samples.spring.security.oauth2;

import com.bivektor.security.oauth2.client.PkceWithClientAuthenticationOAuth2AuthorizationRequestResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
@EnableMethodSecurity
public class OAuth2ClientConfig {

  @Bean
  public SecurityFilterChain oauth2ClientSecurityFilterChain(
      HttpSecurity http,
      ClientRegistrationRepository clientRegistrationRepository
  ) throws Exception {
    http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/oauth2/token/**")
        .permitAll()
        .anyRequest()
        .authenticated());

    String loginEndpointUri = "/oauth2/authorization";

    var authorizationRequestResolver =
        new PkceWithClientAuthenticationOAuth2AuthorizationRequestResolver(
            new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository,
                loginEndpointUri
            )
        );

    http.oauth2Login(login -> login.authorizationEndpoint(endpoint -> {
      endpoint.baseUri(loginEndpointUri);
      endpoint.authorizationRequestResolver(authorizationRequestResolver);
    }));

    return http.build();
  }
}

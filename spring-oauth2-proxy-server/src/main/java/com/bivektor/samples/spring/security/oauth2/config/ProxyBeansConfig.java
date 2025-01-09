package com.bivektor.samples.spring.security.oauth2.config;

import com.bivektor.security.oauth2.server.proxy.DefaultProxyAuthorizationManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Configuration(proxyBeanMethods = false)
public class ProxyBeansConfig {

  @Bean
  public DefaultProxyAuthorizationManager proxyAuthorizationManager(
      RegisteredClientRepository registeredClientRepository
  ) {
    return new DefaultProxyAuthorizationManager(registeredClientRepository);
  }
}

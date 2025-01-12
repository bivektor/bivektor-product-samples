plugins {
  id("java")
  id("org.springframework.boot") version "3.4.1"
}

apply(plugin = "io.spring.dependency-management")

group = "com.bivektor.samples.spring.security.oauth2"
version = "1.0-SNAPSHOT"

repositories {
  mavenLocal()
  mavenCentral()
}

dependencies {
  implementation("org.springframework.boot:spring-boot-starter-web")
  implementation("org.springframework.boot:spring-boot-starter-oauth2-authorization-server")
  implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
  implementation("com.bivektor.security.oauth2:bivektor-spring-oauth2-auth-server-proxy:1.3.0-beta")
}

java {
  toolchain {
    languageVersion = JavaLanguageVersion.of(17)
  }
}

tasks.test {
  useJUnitPlatform()
}
# Bivektor Spring OAuth2 Login Proxy Server (Beta)


## Use Case
In many enterprise and government networks, multiple applications need to authenticate users through
a central OAuth2 authorization server. However, due to strict governance policies and time-consuming
legislative processes, creating and managing separate OAuth2 clients for each application becomes
impractical. As a result, all applications must share a single OAuth2 client registration.

OAuth2 proxy server addresses this challenge by acting as an intermediary between client
applications and the OAuth2 authorization server. It maps incoming authentication requests from
multiple applications to the single shared client, managing the complete OAuth2 flow between the
applications and the authorization server.

1. **Initial Login**: Each application initiates the `authorization_code` login flow through the proxy.
This is simply a redirection from the application's login page to the proxy server's login page
for the specific authorization server.


2. **Redirect and Temporary Storage**: The proxy temporarily stores application's authorization
request and redirects to the target authorization server. Upon successful authentication,
generates an OAuth2 Authorization code and stores it along with the authorization
information (access and refresh tokens) obtained from the OAuth2 server.


3. **Redirect to Originating Application**: The proxy identifies the application that 
initiated the login and redirects the user back to it.


3. **Token Exchange**: The application then contacts the proxy's token endpoint to exchange
an authorization code or grant for the actual access and refresh tokens initially obtained
by the proxy.

This setup allows multiple applications to use a single OAuth2 client for login while
maintaining separation between them and ensuring each application receives the correct tokens.

## Implementation
Proxy server is a typical Spring Boot application with the following main components:  

**[Spring OAuth2 Client Login](https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html#oauth2-client)**: Handles login with the registered target authorization servers

**[Spring OAuth2 Authorization Server](https://docs.spring.io/spring-authorization-server/reference/getting-started.html)**: Handles token exchange with the registered 
application clients after authentication with the target authorization server

**Bivektor Spring OAuth2 Proxy**: Our internal components that coordinate the proxy
authentication and authorization. Note that these components are provided as compiled binaries.
Please contact us on [bivektor.com](http://bivektor.com) or via [email](mailto:info@bivektor.com) in case you need 
further support or access to the source code.

For local testing, we provided a docker compose file at the project root for running a
local [KeyCloak](https://www.keycloak.org/) server at HTTP 8181 port. Execute the command
`docker compose up` to start the server and `docker compose down` for stopping it. KeyCloak admin credentials
are `admin` / `admin`

### Proxy Authorization Code Authentication Flow

1. Client application sends a login request to Spring's standard oauth2 login endpoint
at `outh2/authorization/$targetClientId?client_id=$sourceClientId` where `$targetClientId` 
is the **registration ID** of the client that represents the target authorization server
configured under the `spring.security.oauth2.client` configuration property. 
For this sample, this value is `keycloak` as we have only one login client configured. `$sourceClientId`
is the OAuth2 Client ID (not the registration ID) of the client that represents
the application that is logging through the proxy. Such clients are represented by the `RegisteredClient`
class in Spring Authorization Server. We configure them under the `spring.security.oauth2.authorizationserver.client`
configuration key. Again for this example, we have only one `RegisteredClient` whose client ID is 
`demoClient`. In addition to its client id, the client can send PKCE parameters as well which is explained below. 


2. Proxy request is detected, validated and stored. Http request is redirected to the target authorization server


3. Upon successful authentication, proxy server creates a new random Authorization Code and 
redirects back to the application that initiated the login. Authorization Code generation is done by Spring
Authorization Server's default algorithm.


4. Client application executes the token exchange flow by posting to the Spring Authorization Server's
token endpoint (`/oauth2/token` by default) and obtains the access and refresh token previously
provided by the target authorization server to the proxy server. Proxy server supports proxy and non-proxy
authorizations such that, non-proxy authorizations are handled by the default authorization server logic where
new tokens are generated while proxy authorizations return the tokens retrieved from the target authorization
server. For proxy authorizations, these tokens are immediately deleted after the first successful token
exchange.
Note that, all standard authentication providers configured by Spring's default endpoint configuration
apply here in accordance with the oauth2 standards such as client authentication through `client_secret_basic`
or `client_secret_post` methods as well as `code_challenge` verification.


5. Once the application obtains the access token, all communication except for the refresh token flow
happens between the application and the target authorization server. If the authorization server
provided a refresh token, client application requests a new access token with the refresh token 
from the proxy server. Proxy server obtains the access token from the authorization server
and returns to the client application without storing the tokens.

### Persistence of Authorization Data
Generated authorization codes and associated access and refresh tokens are by default stored in 
an in-memory repository. It is also possible to store them in a RDBMS using `JdbcOAuth2AuthorizationService`
Note that authorization codes are invalidated after first use and associated access & refresh tokens
are deleted.

### Authorization Code Lifetime
Authorization code lifetime is configured by the `AuthorizationCodeTimeToLive` setting in 
`RegisteredClient`'s `TokenSettings`. If no value is configured for the client, then it is set
to 5 minutes by default. This setting can be set in application configuration file.

### Proxy Authorization Request Validation
Proxy server allows you to configure which application client (RegisteredClient) is allowed
to which authorization server client. For instance, you can have one application to 
proxy log in via your Google Login client while another application is allowed to Facebook
login or none. This validation is enabled
by default and configured by the `RegisteredClient`'s `ClientSettings` setting 
named `bivektor-proxy-allowed-client-ids`. The setting should contain a comma separated list of 
allowed OAuth2 Login client ids.  To allow all login clients for a specific RegisteredClient, set this value to `*`

Note that, such settings are not configurable via application config files. You have to set 
them programmatically using `RegisteredClientRepository`. For demo purposes, this validation is entirely
disabled in this example project and indicated with a comment in the code.

### PKCE Authentication 
Proxy server supports PKCE authentication both between the client application and the proxy 
server and between the proxy server and the target authorization server. 

* **Between Proxy Server and Target Server:** This is standard flow handled by the Spring OAuth2
Login components via an auto-generated `code challenge` and `code verifier` pair.


* **Between Client Application and Proxy Server:** Verification happens at the proxy server without
contact with the target server. Client application sends the `code_challenge` 
and `code_challenge_method` parameters along with the `client_id` parameter 
in the login request. Note that Spring OAuth2 Client doesn't support PKCE and Client Credentials
authentication at the same time. See [our sample here](https://github.com/bivektor/bivektor-product-samples/blob/main/spring-oauth2-client/combined-pkce-with-client-credentials/README.md) for a detailed discussion and a workaround. Note that, using that approach with the proxy
server requires a custom `ProxyOAuth2AuthorizationRequestResolver.requestBuilderCustomizer` to keep custom scopes
in the returned authorization request before it is passed to the PKCE handling authorization resolver. Otherwise,
returned request would contain only the scopes requested by the proxy client application losing the default
scopes configured for the `ClientRegistration` object 


**PKCE together with Client Authentication**: Spring authorization server's token endpoint
supports both PKCE and client credentials authentication at the same time. If code_challenge 
was sent in the login request, then during token exchange, PKCE authentication is required. 
But client can still send its client credentials and the server validates client credentials as well.
Note that this is not an OAuth2 standard as described above. KeyCloak server behaves
the same way when both Client Authentication and PKCE are enabled for a specific client. 

## Running the Project

1. Start the local KeyCloak server as described above
2. Create a client in KeyCloak with Client ID = `spring-test`. Configure client credentials
authentication and/or PKCE authentication. Note that depending on the choice, you may have to change
`client-authentication-method` of the **keycloak** client in the application configuration. For PKCE,
set it to `none`. For client authentication, leave it as `client_secret_basic`. Add `http://localhost:8080/login/oauth2/code/keycloak`
to the valid redirect uri list.
3. Copy the client secret generated by KeyCloak and set it to the `KEYCLOAK_CLIENT_SECRET` environment variable
or replace it with that environment variable in the `application.yml` file
4. Start the Spring boot application via your IDE or with the command `./gradlew(.bat) bootRun`

## Example Login Flows

Below are examples for auth login flows running in dev profile with local keycloak started
as described in the Development Environment section.

Replace the `<authorization_code>` parameter with the `code` parameter you receive
in the URL after successful authentication redirect.

Authorization header should be basic authentication of the client credentials:
`Basic base64(clientId:clientSecret)`

For token exchange, depending on the `client-authentication-methods` of the `demo` client,
instead of sending the client credentials in `Authorization` header, you can send them in
post parameters for `client_secret_post` method, or you can completely skip `client_secret` for
authentication method `none`.

### Standard OAuth Login

#### Login URL
http://localhost:8080/oauth2/authorization/keycloak?response_type=code&client_id=demoClient&redirect_uri=http://localhost:8888/demo-callback&scope=openid+email

Redirect uri http://localhost:8888 is just a dummy address which doesn't have to be working. We'll just
copy the `code` parameter from the URL after authentication.

#### Token Exchange Request
```
POST /oauth2/token HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Authorization: ••••••
Content-Length: 230

code=<authorization_code>&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Fdemo-callback
```

### PKCE Authentication with the Proxy Server

#### Login URL
http://localhost:8080/oauth2/authorization/keycloak?client_id=demoClient&redirect_uri=http://localhost:8888/demo-callback&code_challenge=I1PaRI_vuMvXJt6lmFlmTFylVcGwKQkgmTqgRSA87iU&code_challenge_method=S256

#### Token Exchange with both client credentials and pkce

Both client credentials and pkce is verified.

```
POST /oauth2/token HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Authorization: Basic ZGVtb0NsaWVudDpkZW1v
Content-Length: 336

code=<authorization_code>&code_verifier=DdIlYe3RQ8G2a1NNOP114dTNKjch~h4Vb_gtDbIPl5T_6WCVox6hfuL_-_A-Db55&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Fdemo-callback&code_challenge_method=S256
```

#### Token Exchange with only PKCE

Client credentials are not required. Requires `none` method to be present in `client_authentication_methods`

```
POST /oauth2/token HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 357

client_id=demoClient&code=<authorization_code>&code_verifier=DdIlYe3RQ8G2a1NNOP114dTNKjch~h4Vb_gtDbIPl5T_6WCVox6hfuL_-_A-Db55&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Fdemo-callback&code_challenge_method=S256
```

### Example Spring Boot Test Client Configuration
In order to test the proxy server using a Spring OAuth2 Login client, create a separate spring boot
application add spring oauth2 client dependencies. Define the proxy server as a login client
in your application configuration file as shown below:

```
server:
  port: 3002
  
spring:
  security:
    oauth2:
      client:
        registration:
          demo:
            provider: proxyProvider
            client-id: demoClient
            client-secret: demo
            authorization-grant-type: authorization_code
            scope: openid,profile,email
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            client-name: Proxy client
            client-authentication-method: client_secret_basic
        provider:
          proxyProvider:
            issuer-uri: http://localhost:8080
            authorization-uri: http://localhost:8080/oauth2/authorization/keycloak
            user-info-uri: http://localhost:8181/realms/master/protocol/openid-connect/userinfo
```

`user-info-uri` must point to the target authorization server rather than the proxy server.
With oauth2-client starter (`org.springframework.boot:spring-boot-starter-oauth2-client`) and
default configuration, auto generated login page displays a login link to the proxy server.
Note that, with this configuration, you must define the redirect uri `http://localhost:3002/login/oauth2/code/demo`
as a valid uri for the associated client in the proxy server as we have done for this example
project.

## Known Limitations
* Exception handling is currently limited to basic OAuth2 authentication failures. While the proxy 
server handles these failures, additional testing is needed for errors that may occur before authentication 
processing or during token exchange. The primary goal is to prevent users from getting stuck at the proxy 
server during any error scenario.


* Token introspection endpoint currently doesn't work for proxy authorizations.


* The proxy server currently supports only the standard OAuth2 authorization code and refresh token flows. 
Other authentication flows are not yet implemented.


* OpenID Connect support is experimental. ID tokens are generated by the proxy server including the 
claims received from the authorization server. Thus, OpenID is supported only if the associated 
authorization server returns an ID token during the initial login flow. 
  * Currently, **User Info** endpoint does not work for proxy authorizations since the access tokens
are not stored by the proxy server. Applications must communicate directly with the target server to retrieve 
user information. While proxying such requests is possible with some customizations, we don't plan
to support this feature. But we are considering an information endpoint that would return the OpenID 
configuration information of the authorization server so that client applications don't have to
predefine them.

  * RP-Initiated logout functionality is planned for the first stable release but is not currently supported.

* The proxy server currently offers some enterprise auditing capabilities through Spring application events 
emitting four application events:
  - **ProxyRequestResolvedEvent**: When a proxy request is detected and redirected to the target server
  - **ProxyAuthenticationSuccessEvent**: When authentication succeeds and redirects back to the application
  - **ProxyAuthenticationFailureEvent**: When the authorization server returns error details to the proxy server before forwarding to the client application
  - **ProxyLoginAuthorizationCreatedEvent**: After the authorization code is created and stored

  Additional details are available in DEBUG logs. We plan to enhance auditing capabilities in future releases without requiring customization of core components.

## Release Notes
### 1.4.2-beta
* Fixed a bug that was keeping the users logged in after successful authentication. Ideally, we don't
want users to be logged in to the proxy server once they are redirected back to the originating application
* Proxy authorization request resolution logic now relies on Spring authorization server's
validation and exception handling logic. With this change, redirect uri validation is done earlier to
determine if we can redirect back to the client in case of an error.
* Parameters in the redirect uris when redirecting back to the originating application are now 
properly encoded. Earlier there was a bug that caused some parameters to be sent without proper url encoding.
* Exceptions that may occur in event handlers during event publishing are just logged and ignored 
in order to make sure we always redirect back to the originating application.
* Note that some of these changes are breaking changes in associated component APIs

### 1.4.3-beta
* **Support for refresh token revocation**: Clients can revoke refresh tokens by posting to the token
revocation endpoint (default path: `/oauth2/revoke/`). Proxy server validates and sends the revocation
request to the target authorization server. Revocation endpoint is determined by the `revocation_endpoint`
parameter in `ClientRegistration.providerDetails.configurationMetadata`. For this example, it is 
automatically configured for the `keycloak` client by Spring OAuth2 Client using the associated provider's
openid configuration discovery endpoint. Note that `token_type_hint` parameter is required and it must
be sent as `refresh_token`. Revocation of other token types are not supported. This change requires customization
of the token revocation endpoint as shown in the `OAuth2AuthorizationServerConfiguration` class

## Disclaimer
Proxy server strives to adhere to OAuth2 standards thanks to Spring Security OAuth2 libraries, but
we do not accept any responsibility for potential security vulnerabilities or problems that may arise. 
Please use it only after conducting your own security tests and validating all flows. 
If you have an application requiring high security and need support or access to the source code, 
please [contact us](mailto:info@bivektor.com).

# Bivektor Spring OAuth2 Proxy Login Server


## Use Case
In a network, multiple applications need to log in through a single OAuth2 server. However, this 
server only allows one client to be defined for all these applications.

Therefore, all logins occur through this single client. This server acts as an OAuth2 proxy:

1. **Initial Login**: Each application initiates the login process through the proxy.


2. **Redirect and Temporary Storage**: The proxy temporarily stores application's authorization
request and handles redirect to the target authorization server. Upon successful authentication,
it temporarily stores the authorization information (access and refresh tokens) obtained from 
the OAuth2 server.


3. **Redirect to Originating Application**: The proxy identifies the application that 
initiated the login and redirects the user back to it.

4. **Token Exchange**: The application then contacts the proxy's token endpoint to exchange
an authorization code or grant for the actual access and refresh tokens initially obtained
by the proxy.

This setup allows multiple applications to use a single OAuth2 client for login while
maintaining separation between them and ensuring each application receives the correct tokens.

## Implementation
Proxy server is a typical Spring Boot application with the following dependencies:  

**[Spring OAuth2 Client Login](https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html#oauth2-client)**: Handles login with the target authorization server

**[Spring OAuth2 Authorization Server](https://docs.spring.io/spring-authorization-server/reference/getting-started.html)**: Handles token exchange with the login client after
authentication with the target authorization server

**Bivektor Spring OAuth2 Proxy**: Our internal components that coordinate the proxy
authentication and authorization. Note that source code is not provided for these components.
Please get in touch with us via email in case you need support or the source code for legal
reasons.

For local testing, we provided a docker compose file at the project root for running a 
local [KeyCloak](https://www.keycloak.org/) server at HTTP 8181 port. Execute the command
`docker compose up` to start the server and `docker compose down` for stopping it.

### Proxy Authentication Flow

Client application sends a login request to Spring's standard oauth2 login endpoint
at `outh2/authorization/$targetClientId?client_id=$sourceClientId` where `$targetClientId` 
is the **registration ID** of the client that represents the target authorization server
configured under the `spring.security.oauth2.client` configuration property. 
For this sample, this value is `keycloak` as we have only one login client configured.

1. `$sourceClientId` is the OAuth2 Client ID (not the registration ID) of the client that represents
the application that is logging through the proxy. These clients are represented by the `RegisteredClient`
class in Spring Authorization Server. We configure them under the `spring.security.oauth2.authorizationserver.client`
configuration key. Again for this example, we have only one RegisteredClient whose client ID is 
`demoClient`. 

2. Proxy login request is detected by `ProxyOAuth2AuthorizationRequestResolver`, validated and attached
to the original authorization request that will be used for authenticating with the target authorization
server.

3. Default Spring OAuth2 Client components redirect the request to the target server, obtain the 
resource owner tokens (access & refresh tokens) and store it for future access.                                                                      

4. `ProxyAuthenticationSuccessHandler` class processes the authentication. For non-proxy requests,
it delegates to the Spring's default authentication handler. For proxy requests, it creates
a new authorization code and redirects back to the application that initiated the login.

5. Client application executes the token exchange process by posting to the Spring Authorization Server's
token endpoint (`/oauth2/token` by default) and obtains the access and refresh token previously
provided by the target authorization server to the proxy server. Note that,
all standard authentication providers configured by Spring's default endpoint configuration apply
here in accordance with the oauth2 standards such as client authentication through client_secret_basic
or client_secret_post methods as well as code_challenge verification.

### Persistence of the Authorization Data
Generated authorization codes and associated access and refresh tokens are by default stored in 
an in-memory repository, and they are removed after the client application successfully exchanges 
the code for the access and refresh tokens. This is often the preferred behavior as there is no
reason to keep this data for long. To customize this behavior, probably for auditing reasons,
see javadoc for `ProxyOAuth2AuthorizationCodeAuthenticationProvider`


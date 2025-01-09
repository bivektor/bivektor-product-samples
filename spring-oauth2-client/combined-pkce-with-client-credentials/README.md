# Combined OAuth2 Authentication with PKCE and Client Credentials

## The Problem

Some authorization servers require both PKCE (Proof Key for Code Exchange) and client credentials simultaneously. 
This is an unusual requirement since PKCE was designed specifically for public clients that cannot securely store credentials. 
While this combination may seem counterintuitive, some servers implement it as an additional security measure 
even for confidential clients. For more background, 
see [this discussion](https://stackoverflow.com/questions/63057801/do-we-really-need-client-secret-to-get-access-token-on-pkce-flow).

Spring OAuth2 Client doesn't natively support this combination, as it only allows setting a single 
`client-authentication-method`. We needed a solution that wouldn't require extensive modifications 
to Spring's OAuth2 implementation.

## Our Solution

We implemented a lightweight solution using a marker scope called `__pkce__` in the client configuration. 
When this scope is present, it signals that both authentication methods should be used. 
Our custom `OAuth2AuthorizationRequestResolver` detects this marker scope, 
removes it from the request, and applies the necessary PKCE parameters.

The implementation is handled by `PkceWithClientAuthenticationOAuth2AuthorizationRequestResolver` 
and configured in `config/OAuth2ClientConfig`.

While the code itself is straightforward, we're sharing this implementation to document the approach
and encourage discussion around this authentication pattern. It provides a clean workaround for 
scenarios requiring both PKCE and client credentials without compromising Spring's OAuth2 client architecture.

## Running the project
`application.yml` contains a single client which you can test with a local KeyCloak server running
at 8181 port. Create a client in KeyCloak and enable both Client Authentication and PKCE. Also configure
client secret and either replace the secret with the `KEYCLOAK_CLIENT_SECRET` environment variable or
set the environment variable to the secret.

Next, visit `http://localhost:8080/login` and click the **KeyCloak** link to log in with your KeyCloak
server. 

Project contains a **docker-compose** file that you can use for starting the KeyCloak server 
with docker and log in with user credentials `admin`/`admin`



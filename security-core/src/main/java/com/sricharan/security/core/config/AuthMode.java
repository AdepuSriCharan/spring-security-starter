package com.sricharan.security.core.config;

/**
 * Selects the authentication mechanism used by the security starter.
 *
 * <p>Set via {@code security.auth-mode} in {@code application.properties}.
 * If not specified, defaults to {@link #INTERNAL}.
 *
 * <h3>Quick Reference</h3>
 * <table border="1" cellpadding="5">
 *   <tr><th>Mode</th><th>Token Issuer</th><th>Required Properties</th></tr>
 *   <tr>
 *     <td>{@code INTERNAL}</td>
 *     <td>Your application</td>
 *     <td>{@code security.jwt.secret}</td>
 *   </tr>
 *   <tr>
 *     <td>{@code OAUTH2}</td>
 *     <td>Any OIDC provider (Auth0, Azure AD, Okta, etc.)</td>
 *     <td>{@code spring.security.oauth2.resourceserver.jwt.issuer-uri}</td>
 *   </tr>
 *   <tr>
 *     <td>{@code KEYCLOAK}</td>
 *     <td>Keycloak</td>
 *     <td>{@code spring.security.oauth2.resourceserver.jwt.issuer-uri},
 *         optionally {@code security.keycloak.client-id}</td>
 *   </tr>
 * </table>
 *
 * <h3>Usage Examples</h3>
 * <pre>
 * # INTERNAL mode (default — omit property or set explicitly):
 * security.auth-mode=INTERNAL
 * security.jwt.secret=my-256-bit-secret
 * security.public-endpoints=/register,/public
 *
 * # OAUTH2 mode:
 * security.auth-mode=OAUTH2
 * spring.security.oauth2.resourceserver.jwt.issuer-uri=https://login.example.com
 * security.oauth2.username-claim=preferred_username
 * security.oauth2.roles-claim=roles
 *
 * # KEYCLOAK mode:
 * security.auth-mode=KEYCLOAK
 * spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9090/realms/my-realm
 * security.keycloak.client-id=my-app
 * </pre>
 */
public enum AuthMode {

    /**
     * Built-in JWT mode (default).
     *
     * <p>The starter manages its own JWT issuance and verification.
     * Provides {@code /login}, {@code /refresh}, and {@code /logout} endpoints automatically.
     *
     * <p>Required properties:
     * <ul>
     *   <li>{@code security.jwt.secret} — HMAC signing key (mandatory)</li>
     *   <li>{@code security.jwt.expiration-ms} — access token lifetime (default: 1 hour)</li>
     *   <li>{@code security.jwt.refresh-expiration-ms} — refresh token lifetime (default: 7 days)</li>
     * </ul>
     */
    INTERNAL,

    /**
     * OAuth2 Resource Server mode.
     *
     * <p>Delegates JWT validation to Spring's OAuth2 Resource Server support.
     * Compatible with any OIDC-compliant provider: Auth0, Azure AD, Okta, Google, etc.
     * No {@code /login} endpoint is provided — tokens are obtained directly from the IdP.
     *
     * <p>Required properties:
     * <ul>
     *   <li>{@code spring.security.oauth2.resourceserver.jwt.issuer-uri} — IdP issuer URL</li>
     * </ul>
     *
     * <p>Optional claim mapping (defaults follow OIDC conventions):
     * <ul>
     *   <li>{@code security.oauth2.username-claim} — default: {@code preferred_username}</li>
     *   <li>{@code security.oauth2.user-id-claim} — default: {@code sub}</li>
     *   <li>{@code security.oauth2.roles-claim} — default: {@code roles}</li>
     *   <li>{@code security.oauth2.permissions-claim} — default: {@code permissions}</li>
     * </ul>
     *
     * <p>Requires {@code spring-boot-starter-oauth2-resource-server} on the classpath.
     */
    OAUTH2,

    /**
     * Keycloak-specific mode.
     *
     * <p>Extends {@link #OAUTH2} with automatic extraction of Keycloak's nested
     * claim structures: {@code realm_access.roles} and
     * {@code resource_access.&lt;client&gt;.roles}.
     *
     * <p>Required properties:
     * <ul>
     *   <li>{@code spring.security.oauth2.resourceserver.jwt.issuer-uri} — Keycloak realm URL</li>
     * </ul>
     *
     * <p>Optional Keycloak-specific configuration:
     * <ul>
     *   <li>{@code security.keycloak.client-id} — enables client-level role extraction</li>
     *   <li>{@code security.keycloak.realm-access-claim} — default: {@code realm_access}</li>
     *   <li>{@code security.keycloak.resource-access-claim} — default: {@code resource_access}</li>
     *   <li>{@code security.keycloak.roles-key} — default: {@code roles}</li>
     * </ul>
     *
     * <p>Requires {@code spring-boot-starter-oauth2-resource-server} on the classpath.
     */
    KEYCLOAK
}

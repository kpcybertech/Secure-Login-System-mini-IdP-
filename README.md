SecureLoginSystem is a full-stack Python identity and access management project that demonstrates how modern authentication and provisioning can be built from the ground up. It combines secure login flows, standards-based federation protocols, and advanced detection logic into a single, modular system.

At its core, the system provides strong password protection with bcrypt, enforced MFA through TOTP codes, and role-based access control for both user and admin accounts. Beyond the basics, it implements enterprise-grade capabilities including structured audit logging, token revocation, and optional Splunk HEC integration for centralized monitoring.

On the standards side, SecureLoginSystem includes a minimal OpenID Connect (OIDC) provider that signs ID and access tokens using RS256 with rotating keys and publishes a JWKS endpoint for secure validation. It also exposes a SCIM 2.0 API for identity lifecycle management, supporting CRUD operations for both users and groups.

Together, these features make SecureLoginSystem a learning-ready platform that mirrors how professional identity providers like Okta or Azure AD handle authentication, authorization, and provisioning — but in a compact Python project you can run locally and extend.

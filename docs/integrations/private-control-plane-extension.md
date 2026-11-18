# Private control-plane extension boundary

## Purpose

This document records how a separate, private enterprise control plane can extend the Agentdesktop controller without changing the endpoint agent's native behavior or placing proprietary business logic in this public repository.

The integration is compiled into a controller executable. The current upstream extension API is not a dynamic plugin loader.

## Existing extension API

The controller library exposes `application::run(config, database, extensions)`. Its `management::Extensions` value accepts:

- `authentication: Option<Arc<dyn auth::Provider>>`
- `routes: Vec<ProtectedRoutes>`
- `assets: Option<AssetLookup>`

The standard controller executable currently invokes `application::run(..., Extensions::default())`. A separate executable can provide a custom provider, routes, and embedded UI assets while continuing to reuse the native fleet controller, database, enrollment, device certificates, OIDC enrollment, gateway JWT issuance, and usage ingestion.

### Authentication provider

Implement `management::auth::Provider` in the private executable/library.

The provider owns the browser session contract and credential verification. Its `authenticate` method must return a verified `Principal` containing issuer, subject, credential kind, verified claims, and authentication timestamps. It must not accept browser-supplied role or tenant claims as trusted identity.

Its `check` method evaluates the requested operation against the concrete resource and current authorization state. The principal is identity evidence, not a reusable authorization grant.

Authenticated admin mode requires a compiled-in provider. The controller rejects an authenticated configuration without one and rejects a provider when local mode is selected.

### Protected API routes

Register extension APIs through `ProtectedRoutes`. The router applies the shared authentication middleware to these routes. Authentication alone does not authorize an operation.

Every handler must extract `auth::Context` and call `Context::require(AccessRequest { verb, resource_class, resource })` before reading protected data or mutating state. Never trust a route path, request body, UI visibility, or client-provided role as an authorization decision.

The existing `Verb` set is `Read`, `List`, `Create`, `Update`, and `Delete`. Use stable resource-class permission names and concrete resource IDs for resource-scoped decisions.

### Embedded management UI

The frontend exports `ControllerExtension` and `App({ extensions })`. Each extension contributes a path, label, permission hint, icon, and React component. The shell hides navigation entries when the session lacks the named permission, and the route checks the same hint again.

These frontend checks are usability controls only. Every API operation must still be authorized by the backend.

The default frontend entry point currently renders `<App />` without extensions. A private UI build must provide its own entry point that passes the extension list. The controller can serve a complete embedded asset bundle through `AssetLookup`; it falls back to the built-in bundle when no custom lookup is supplied.

### HTTP protections retained by the controller

The management router applies the existing deployment-level HTTP policy, including origin checks for unsafe browser requests, loopback-host checks in local mode, request timeouts, security headers, and private/no-store response caching. Authenticated admin transport must use the configured HTTPS/TLS mode.

Do not bypass these safeguards when adding routes or serving custom assets.

## Identity and directory integration

Directory integration belongs in the private backend/provider, never in the browser or endpoint desktop process. Use LDAPS or another explicitly approved secure directory transport, a least-privilege service account, secret storage outside source control, bounded timeouts, and redacted diagnostics.

Directory synchronization establishes identity evidence only. It must not automatically grant AI access, project membership, roles, or quotas. Authentication, identity mapping, authorization, entitlement, and audit remain separate operations.

## Data and tenant isolation

The private control plane must own its organization, project, department, team, membership, entitlement, and policy data. Users must have one canonical identity and may hold multiple memberships without duplicate user records.

Every list, read, create, update, delete, analytics query, and export must be scoped and authorized on the server. A caller must not be able to switch tenant scope by changing an identifier, query parameter, header, or frontend state.

## Required verification before production

- Authenticated mode fails startup without a provider.
- Local mode cannot accidentally bypass an installed authenticated provider.
- Session login, logout, refresh, expiry, and recent-auth requirements are tested.
- API-only service credentials cannot be used as browser sessions.
- Every extension handler checks operation and resource authorization.
- UI permission hints never replace backend checks.
- Cross-origin mutation, cookie, host-header, cache, and timeout protections remain active.
- Tenant/project/department/team isolation is tested with positive and negative cases.
- Directory outage and malformed directory responses fail safely.
- Directory sync does not grant entitlements.
- Private UI assets are embedded and missing hashed assets return 404 rather than HTML.
- Existing fleet enrollment, device identity, native configuration reconciliation, supported tool discovery, and usage ingestion regressions are tested.
- The public upstream feature set remains intact.

## Source locations

- `crates/controller/src/application.rs`
- `crates/controller/src/management.rs`
- `crates/controller/src/management/auth.rs`
- `crates/controller/src/management/auth/authentication.rs`
- `crates/controller/src/management/auth/authorization.rs`
- `crates/controller/src/management/http.rs`
- `crates/controller/src/management/handlers.rs`
- `frontend/controller/src/extensions.ts`
- `frontend/controller/src/App.tsx`
- `frontend/controller/src/components/ControllerShell.tsx`
- `frontend/controller/src/index.ts`
- `frontend/controller/src/main.tsx`

This document is an integration contract, not evidence that the private control plane, directory connector, or production deployment has been implemented.

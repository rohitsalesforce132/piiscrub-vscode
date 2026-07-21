# Change Log

## [0.2.0] — 2026-07-21

### Changed — Full Sensitive Data Guard
- **Renamed** from "PII Guard" to "Data Guard" — now scrubs ALL sensitive data, not just PII
- **60+ detection patterns** across 8 categories (up from 15 PII-only patterns)

### Added — 7 New Detection Categories
- **Secrets**: API keys (OpenAI, AWS), Bearer tokens, JWT tokens, private keys (PEM), passwords, client IDs, auth headers
- **Connection Strings**: SQL Server, PostgreSQL, MySQL, MongoDB, Redis, Azure Storage, Service Bus, Event Hub, Cosmos DB
- **Cloud Resources**: Azure resource IDs, Azure GUIDs/tenant IDs, ACR servers, ARM template refs, Bicep refs, AWS ARNs, GCP project refs
- **Infrastructure**: Internal hostnames (.att.com, .corp, .internal, .local), DB hosts, K8s service names, localhost endpoints, internal URLs
- **File Paths**: Linux paths (/home, /var, /opt), Windows paths (C:\Users), UNC paths (\\\\server), .env files
- **Code & Config**: Stack traces (Python, Java), env vars, Docker images, K8s namespaces, K8s secrets, bash history
- **IDs**: User IDs, session IDs, request IDs, correlation IDs, trace IDs

### Kept from v0.1.0
- @piisafe chat participant
- Status bar toggle (🛡️ shield)
- Clipboard scrub command
- Custom patterns via settings.json
- Block mode setting
- Zero runtime dependencies

## [0.1.0] — 2026-07-21

### Added
- Initial release — 15 PII patterns (email, SSN, phone, credit card, API keys, etc.)

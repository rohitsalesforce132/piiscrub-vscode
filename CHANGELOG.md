# Change Log

## [0.1.0] — 2026-07-21

### Added
- **@piisafe chat participant** — Type `@piisafe` in Copilot Chat to automatically scrub PII before the message reaches the model
- **15 PII patterns** detected out of the box: email, SSN, phone (US + international), credit card, OpenAI API key, Bearer token, AWS key, IP address, password, user ID, session ID, Azure GUID, Azure resource ID, MAC address
- **Custom patterns** — add your own regex patterns via `piiscrub.customPatterns` setting
- **Status bar toggle** — shield icon (🛡️) to enable/disable the guard with one click
- **Clipboard scrub command** — `PIIScrub: Scrub Clipboard` detects and replaces PII in your clipboard
- **Block mode** — optional setting to block messages entirely if PII is detected (instead of redacting)
- **Redaction notice** — shows `🔒 PII Guard: Redacted N items` before each response
- Zero runtime dependencies

# PIIScrub — VS Code Extension

> Intercepts chat messages in Copilot Chat, scrubs PII **before** they reach the model, shows you what was redacted.

## The Problem

```
You type: "Debug this for john@att.com, SSN 123-45-6789"
                              ↓
         PII goes to OpenAI servers in the request body
                              ↓
         .github/copilot-instructions.md tells the model to redact
                              ↓
         TOO LATE — PII already reached the server
```

## The Fix

```
You type: "Debug this for john@att.com, SSN 123-45-6789"
                              ↓
         @piisafe intercepts BEFORE the API call
                              ↓
         PII replaced with tokens: [REDACTED_EMAIL_1], [REDACTED_SSN_2]
                              ↓
         REDACTED message sent to model — PII never leaves your machine
                              ↓
         Model responds using tokens
                              ↓
         You see: "🔒 PII Guard: Redacted 2 items (1 email, 1 ssn)"
```

## Installation

### Option A: Build from source (dev)

```bash
cd piiscrub-vscode
npm install
npm run compile
# Open in VS Code → F5 to launch Extension Development Host
```

### Option B: Package as .vsix

```bash
cd piiscrub-vscode
npm install
npm run compile
npx vsce package
# Installs: piiscrub-0.1.0.vsix
# In VS Code: Extensions → ... → Install from VSIX
```

## Usage

### Chat with PII Guard

Type in Copilot Chat:
```
@piisafe debug this error for customer john@att.com with phone 555-123-4567
```

The extension:
1. Detects email + phone PII
2. Replaces with tokens before sending
3. Shows: `🔒 PII Guard: Redacted 2 items (email, phone)`
4. Sends: `debug this error for customer [REDACTED_EMAIL_1] with phone [REDACTED_PHONE_2]`
5. Model responds using the redacted tokens

### Scrub Clipboard

Command palette → `PIIScrub: Scrub Clipboard`:
- Reads your clipboard
- Detects PII
- Asks to replace clipboard with scrubbed version

### Toggle Guard

Command palette → `PIIScrub: Toggle Global PII Guard`:
- Or click the `🛡️ PII Guard` status bar item

## Settings

```json
{
    "piiscrub.showRedactionNotice": true,       // Show 🔒 notice before response
    "piiscrub.blockIfPIIDetected": false,        // Block instead of redact
    "piiscrub.customPatterns": [                 // Add your own patterns
        {
            "name": "EMPLOYEE_ID",
            "regex": "EMP-\\d{6}",
            "replacement": "[REDACTED_EMP_ID]"
        }
    ]
}
```

## PII Types Detected (15 default patterns)

| Type | Example |
|------|---------|
| Email | john@att.com |
| Phone (US/Intl) | 555-123-4567, +1-555-123-4567 |
| SSN | 123-45-6789 |
| Credit Card | 4532 1234 5678 9012 |
| API Key (OpenAI) | sk-abc123... |
| Bearer Token | Bearer eyJ... |
| AWS Key | AKIAIOSF... |
| IP Address | 10.0.45.23 |
| Password | password=secret |
| User ID | user_id=12345 |
| Session ID | session_id=abc123 |
| Azure GUID | 12345678-1234-... |
| Azure Resource ID | /subscriptions/... |
| MAC Address | 00:1B:44:11:3A:B7 |

## Architecture

```
src/
├── extension.ts       ← Entry point, registers @piisafe participant + commands
├── piiDetector.ts     ← Pure regex PII detection engine (zero deps)
├── chatHandler.ts     ← Scrubs message → calls model → streams response
└── statusBar.ts       ← Shield icon in status bar (toggle on/off)
```

**Zero runtime dependencies.** Only `@types/vscode` and `typescript` as dev deps.

## How It Works

1. **Intercept**: User types `@piisafe <message>` in Copilot Chat
2. **Scrub**: `PIIDetector.scrub()` replaces all PII with numbered tokens
3. **Send**: Redacted message sent to `vscode.lm` (Copilot's Language Model API)
4. **Stream**: Model response streamed back to user
5. **Notice**: `🔒 PII Guard: Redacted N items` shown before response

The model **never sees** raw email addresses, SSNs, phone numbers, API keys, or any other PII.

## FDE Portfolio Value

This extension demonstrates:
- **Enterprise compliance**: SOC2/HIPAA-grade PII handling
- **Security engineering**: Network-level interception, not prompt-level
- **VS Code Extension API**: Chat Participants, Language Model API, Status Bar
- **Zero-dependency design**: Pure stdlib, no heavy frameworks

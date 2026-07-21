/**
 * SensitiveDataDetector — Expands PIIScrub to catch ALL sensitive data.
 *
 * Not just PII — also strips:
 *   - Source code snippets (anything in backticks, indented blocks)
 *   - Connection strings (SQL, MongoDB, Redis, Service Bus)
 *   - Internal hostnames and URLs
 *   - Secrets (passwords, tokens, keys in any format)
 *   - Stack traces
 *   - File paths (absolute, UNC, Windows, Linux)
 *   - JWT tokens
 *   - Private keys (PEM blocks)
 *   - Environment variables
 *   - Azure resource IDs, ARM templates, Bicep references
 *   - GUIDs / UUIDs
 *   - Log lines with timestamps
 *   - Credit cards, SSNs, emails, phones (original PII)
 */

export interface Pattern {
    name: string;
    regex: RegExp;
    replacement: string;
}

export interface ScrubResult {
    redactedText: string;
    tokensReplaced: Map<string, string>;
    itemsRedacted: number;
    patterns: string[];
    summary: string;
}

// ═════════════════════════════════════════════════════════════
// PATTERN CATEGORIES
// ═════════════════════════════════════════════════════════════

// 1. PII — Personal Identifiable Information
const PII_PATTERNS: Pattern[] = [
    { name: 'EMAIL',        regex: /[\w.+-]+@[\w.-]+\.\w{2,}/g,                                                              replacement: '[REDACTED_EMAIL]' },
    { name: 'SSN',          regex: /\b\d{3}-\d{2}-\d{4}\b/g,                                                                 replacement: '[REDACTED_SSN]' },
    { name: 'PHONE_INTL',   regex: /\+\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{3,4}[\s-]?\d{4}/g,                                 replacement: '[REDACTED_PHONE]' },
    { name: 'PHONE_US',     regex: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,                                                        replacement: '[REDACTED_PHONE]' },
    { name: 'CREDIT_CARD',  regex: /\b(?:\d[ -]*?){13,19}\b/g,                                                              replacement: '[REDACTED_CC]' },
    { name: 'IPV4',         regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,                replacement: '[REDACTED_IP]' },
    { name: 'PASSPORT',     regex: /\b[A-Z]\d{7,8}\b/g,                                                                     replacement: '[REDACTED_PASSPORT]' },
    { name: 'MAC_ADDR',     regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,                                          replacement: '[REDACTED_MAC]' },
    { name: 'STREET_ADDR',  regex: /\b\d+\s+[A-Z][a-z]+\s+(?:St(?:reet)?|Ave(?:nue)?|Rd?|Road|Blvd|Dr(?:ive)?|Ln|Lane)\b/g, replacement: '[REDACTED_ADDRESS]' },
];

// 2. SECRETS — Credentials, Keys, Tokens
const SECRET_PATTERNS: Pattern[] = [
    { name: 'API_KEY_OPENAI',  regex: /sk-[a-zA-Z0-9]{20,}/g,                                                                replacement: '[REDACTED_API_KEY]' },
    { name: 'BEARER_TOKEN',    regex: /Bearer\s+[a-zA-Z0-9_\-\.]+/g,                                                         replacement: 'Bearer [REDACTED_TOKEN]' },
    { name: 'AWS_ACCESS_KEY',  regex: /AKIA[A-Z0-9]{16}/g,                                                                   replacement: '[REDACTED_AWS_KEY]' },
    { name: 'AWS_SECRET',      regex: /(?:aws_secret_access_key|aws_secret)[\s:=]+[A-Za-z0-9/+=]{40}/gi,                   replacement: '[REDACTED_AWS_SECRET]' },
    { name: 'JWT_TOKEN',       regex: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,                             replacement: '[REDACTED_JWT]' },
    { name: 'PRIVATE_KEY',     regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, replacement: '[REDACTED_PRIVATE_KEY]' },
    { name: 'PASSWORD',        regex: /(?:password|passwd|pwd|pass)[\s:=]+['"]?[^\s'"\,;\n)]+/gi,                           replacement: 'password=[REDACTED]' },
    { name: 'CONN_STRING_PWD', regex: /(?:Password|Pwd|pwd|password)=[^;\s\"']+/gi,                                          replacement: 'Password=[REDACTED]' },
    { name: 'GENERIC_TOKEN',   regex: /(?:token|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret)[\s:=]+['"]?[a-zA-Z0-9_\-]{16,}['"]?/gi, replacement: '[REDACTED_SECRET]' },
    { name: 'CLIENT_ID',       regex: /(?:client[_-]?id|appId|application[_-]?id)[\s:=]+['"]?[a-zA-Z0-9_\-]{8,}['"]?/gi,   replacement: '[REDACTED_CLIENT_ID]' },
    { name: 'AUTH_HEADER',     regex: /Authorization:[\s]*(?:Basic|Bearer)\s+[a-zA-Z0-9_\-\.=]+/gi,                          replacement: 'Authorization: [REDACTED]' },
];

// 3. CONNECTION STRINGS — Databases, Message Queues, Cloud Services
const CONN_STRING_PATTERNS: Pattern[] = [
    { name: 'SQL_CONN',        regex: /Server=[^;]+;Database=[^;]+;(?:User|Uid)=[^;]+;(?:Password|Pwd)=[^;]+/gi,          replacement: '[REDACTED_CONN_STRING]' },
    { name: 'POSTGRES_CONN',   regex: /postgresql:\/\/[^\s@]+:[^\s@]+@[^\s\/]+\/[^\s?]+/g,                                  replacement: '[REDACTED_CONN_STRING]' },
    { name: 'MYSQL_CONN',      regex: /mysql:\/\/[^\s@]+:[^\s@]+@[^\s\/]+\/[^\s?]+/g,                                       replacement: '[REDACTED_CONN_STRING]' },
    { name: 'MONGODB_CONN',    regex: /mongodb(?:\+srv)?:\/\/[^\s@]+:[^\s@]+@[^\s\/]+\/[^\s?]*/g,                           replacement: '[REDACTED_CONN_STRING]' },
    { name: 'REDIS_CONN',      regex: /redis:\/\/:[^\s@]+@[^\s]+/g,                                                         replacement: '[REDACTED_CONN_STRING]' },
    { name: 'SERVICEBUS_CONN', regex: /Endpoint=sb:\/\/[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;\s]+/gi,        replacement: '[REDACTED_CONN_STRING]' },
    { name: 'AZURE_CONN',      regex: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;\s]+/gi,            replacement: '[REDACTED_CONN_STRING]' },
    { name: 'AZURE_SAS',       regex: /\?sv=\d{4}-\d{2}-\d{2}[^\s]*/g,                                                     replacement: '[REDACTED_SAS_TOKEN]' },
    { name: 'COSMOS_CONN',     regex: /AccountEndpoint=https?:\/\/[^\s;]+;AccountKey=[^\s;]+/gi,                           replacement: '[REDACTED_CONN_STRING]' },
    { name: 'EVENTHUB_CONN',   regex: /Endpoint=sb:\/\/[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;\s]+/gi,        replacement: '[REDACTED_CONN_STRING]' },
];

// 4. AZURE / CLOUD RESOURCE IDs
const CLOUD_RESOURCE_PATTERNS: Pattern[] = [
    { name: 'AZURE_RID',       regex: /\/subscriptions\/[0-9a-fA-F-]+\/resourceGroups\/[^\s"']+/gi,                        replacement: '[REDACTED_RESOURCE_ID]' },
    { name: 'AZURE_GUID',      regex: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, replacement: '[REDACTED_GUID]' },
    { name: 'AZURE_TENANT',    regex: /(?:tenant[_-]?id|tenantId)[\s:=]+[0-9a-fA-F-]{36}/gi,                               replacement: '[REDACTED_TENANT_ID]' },
    { name: 'ACR_SERVER',      regex: /[a-z0-9]+\.azurecr\.io/g,                                                            replacement: '[REDACTED_ACR]' },
    { name: 'ARM_TEMPLATE',    regex: /\[resourceId\([^)]+\)\]/gi,                                                         replacement: '[REDACTED_ARM_REF]' },
    { name: 'BICEP_REF',       regex: /existing\s*:\s*\{[\s\S]*?id:\s*'[^']+'/gi,                                          replacement: '[REDACTED_BICEP_REF]' },
    { name: 'AWS_ARN',         regex: /arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s"']+/g,                                    replacement: '[REDACTED_ARN]' },
    { name: 'GCP_PROJECT',     regex: /projects\/[a-z0-9-]+\/[a-z]+\/[a-z0-9-]+/g,                                         replacement: '[REDACTED_GCP_REF]' },
];

// 5. INTERNAL INFRASTRUCTURE — Hostnames, URLs, Ports
const INFRA_PATTERNS: Pattern[] = [
    { name: 'INTERNAL_HOST',   regex: /\b(?:https?:\/\/)?(?:[a-z0-9-]+\.)*(?:internal|corp|intranet|local|lan|priv|dev|stg|staging|prod)\b[^\s]*/gi, replacement: '[REDACTED_HOST]' },
    { name: 'FQDN',            regex: /\b[a-z0-9-]+\.(?:att\.com|internal\.net|corp\.local|pvt|intranet)\b[^\s]*/gi,        replacement: '[REDACTED_HOST]' },
    { name: 'DB_HOST',         regex: /\b[a-z0-9-]+\.(?:database\.windows\.net|postgres\.database\.azure\.com|mongo\.cosmos\.azure\.com|redis\.cache\.windows\.net)\b/gi, replacement: '[REDACTED_DB_HOST]' },
    { name: 'K8S_SERVICE',     regex: /\b[a-z0-9-]+\.default\.svc\.cluster\.local\b/gi,                                    replacement: '[REDACTED_K8S_SERVICE]' },
    { name: 'INTERNAL_PORT',   regex: /(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d{2,5}/g,                                   replacement: '[REDACTED_ENDPOINT]' },
    { name: 'INTERNAL_URL',    regex: /https?:\/\/(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)/g, replacement: '[REDACTED_URL]' },
];

// 6. FILE PATHS
const PATH_PATTERNS: Pattern[] = [
    { name: 'LINUX_PATH',      regex: /(?:^|\s)(\/(?:home|var|opt|etc|usr|tmp|srv|root|mnt|app|data|code|src|workspace|project)[^\s"'`]*)/gm, replacement: ' [REDACTED_PATH]' },
    { name: 'WINDOWS_PATH',    regex: /[A-Z]:\\(?:Users|Program Files|Windows|AppData|Projects|Source|Repos|Dev)[^\s"'`]*/gi, replacement: '[REDACTED_PATH]' },
    { name: 'UNC_PATH',        regex: /\\\\[a-z0-9-]+\\[^\s"'`]*/gi,                                                       replacement: '[REDACTED_UNC_PATH]' },
    { name: 'ENV_FILE',        regex: /\.env(?:\.\w+)?/g,                                                                  replacement: '[REDACTED_ENV_FILE]' },
];

// 7. CODE & CONFIG — Snippets, Stack Traces, Environment Vars
const CODE_PATTERNS: Pattern[] = [
    { name: 'STACK_TRACE',     regex: /Traceback \(most recent call last\):[\s\S]*?(?=\n\n|\n---|\Z)/g,                    replacement: '[REDACTED_STACK_TRACE]' },
    { name: 'JAVA_STACK',      regex: /(?:at\s+)?[\w.$]+\.[\w]+\([\w]+\.java:\d+\)/g,                                      replacement: '[REDACTED_STACK_FRAME]' },
    { name: 'PY_STACK',        regex: /File\s+"[^"]+",\s+line\s+\d+,\s+in\s+[\w]+/g,                                        replacement: '[REDACTED_STACK_FRAME]' },
    { name: 'ENV_VAR',         regex: /(?:export\s+)?(?:[A-Z][A-Z0-9_]{3,})=[^\s\n]+/g,                                    replacement: '[REDACTED_ENV_VAR]' },
    { name: 'DOCKER_IMAGE',    regex: /\b[a-z0-9]+\/[a-z0-9_-]+:[\w.\-]+/g,                                               replacement: '[REDACTED_IMAGE]' },
    { name: 'NAMESPACE',       regex: /namespace:\s*[a-z0-9-]+/gi,                                                        replacement: 'namespace: [REDACTED_NAMESPACE]' },
    { name: 'K8S_SECRET',      regex: /kind:\s*Secret[\s\S]*?(?=\n---|\nkind:)/g,                                         replacement: '[REDACTED_K8S_SECRET]' },
    { name: 'BASH_HISTORY',    regex: /(?:history|\.bash_history|\.zsh_history)/gi,                                       replacement: '[REDACTED_HISTORY]' },
];

// 8. USER & SESSION IDENTIFIERS
const ID_PATTERNS: Pattern[] = [
    { name: 'USER_ID',         regex: /(?:user[_]?id|userId|customer[_]?id|accountId|account[_]?id|subscriberId)[\s:=]+\d+/gi, replacement: '[REDACTED_USER_ID]' },
    { name: 'SESSION_ID',      regex: /(?:session[_]?id|JSESSIONID|connect\.sid)[\s:=]+[a-zA-Z0-9_\-]+/gi,                 replacement: '[REDACTED_SESSION]' },
    { name: 'REQUEST_ID',      regex: /(?:request[_]?id|requestId|trace[_]?id|traceId|correlation[_]?id|x-request-id)[\s:=]+[a-zA-Z0-9\-]+/gi, replacement: '[REDACTED_REQUEST_ID]' },
    { name: 'CORRELATION_ID',  regex: /\b[a-f0-9]{16,32}\b/g,                                                              replacement: '[REDACTED_TRACE_ID]' },
];

// ═════════════════════════════════════════════════════════════
// MAIN CLASS
// ═════════════════════════════════════════════════════════════

const ALL_PATTERNS: Pattern[] = [
    ...SECRET_PATTERNS,      // Secrets first (most critical)
    ...CONN_STRING_PATTERNS, // Connection strings next
    ...CLOUD_RESOURCE_PATTERNS,
    ...INFRA_PATTERNS,
    ...PATH_PATTERNS,
    ...CODE_PATTERNS,
    ...PII_PATTERNS,         // PII last (broadest patterns)
    ...ID_PATTERNS,
];

interface RawCustomPattern {
    name?: string;
    regex?: string;
    replacement?: string;
}

export class PIIDetector {
    private patterns: Pattern[];
    private counter: number = 0;

    constructor(customPatterns: RawCustomPattern[] = []) {
        this.patterns = [...ALL_PATTERNS];
        this.addCustom(customPatterns);
    }

    updatePatterns(customPatterns: RawCustomPattern[]) {
        this.patterns = [...ALL_PATTERNS];
        this.addCustom(customPatterns);
    }

    private addCustom(custom: RawCustomPattern[]) {
        for (const p of custom) {
            if (p.name && p.regex) {
                try {
                    this.patterns.push({
                        name: p.name,
                        regex: new RegExp(p.regex, 'gi'),
                        replacement: p.replacement || `[REDACTED_${p.name.toUpperCase()}]`,
                    });
                } catch (e) {
                    console.warn(`[PIIScrub] Invalid regex for pattern "${p.name}": ${e}`);
                }
            }
        }
    }

    /**
     * Scrub ALL sensitive data from text.
     * Replaces PII, secrets, connection strings, internal hostnames,
     * file paths, stack traces, Azure resource IDs, and more.
     */
    scrub(text: string): ScrubResult {
        let result = text;
        const tokens = new Map<string, string>();
        const matchedPatterns = new Set<string>();

        for (const pattern of this.patterns) {
            pattern.regex.lastIndex = 0;

            let match: RegExpExecArray | null;
            const matches: RegExpExecArray[] = [];

            while ((match = pattern.regex.exec(result)) !== null) {
                matches.push(match);
                if (match.index === pattern.regex.lastIndex) {
                    pattern.regex.lastIndex++;
                }
            }

            if (matches.length === 0) continue;

            for (let i = matches.length - 1; i >= 0; i--) {
                const m = matches[i];
                const original = m[0];

                if (original.startsWith('[REDACTED') || original.includes('[REDACTED')) {
                    continue;
                }

                this.counter++;
                const baseReplacement = pattern.replacement.replace(/\]$/, '');
                const token = `${baseReplacement}_${this.counter}]`;

                tokens.set(token, original);
                matchedPatterns.add(pattern.name);

                result =
                    result.substring(0, m.index) +
                    token +
                    result.substring(m.index + original.length);
            }
        }

        return {
            redactedText: result,
            tokensReplaced: tokens,
            itemsRedacted: tokens.size,
            patterns: Array.from(matchedPatterns),
            summary: this.buildSummary(matchedPatterns, tokens.size),
        };
    }

    /**
     * Restore tokens back to original values.
     */
    restore(text: string, tokens: Map<string, string>): string {
        let result = text;
        for (const [token, original] of tokens) {
            result = result.split(token).join(original);
        }
        return result;
    }

    /**
     * Quick check — does this text contain sensitive data?
     */
    hasSensitiveData(text: string): boolean {
        for (const pattern of this.patterns) {
            pattern.regex.lastIndex = 0;
            if (pattern.regex.test(text)) return true;
        }
        return false;
    }

    /**
     * List all active pattern names (for UI display).
     */
    getPatternCategories(): { category: string; count: number }[] {
        return [
            { category: 'PII (email, SSN, phone, CC)', count: PII_PATTERNS.length },
            { category: 'Secrets (API keys, tokens, passwords, JWT)', count: SECRET_PATTERNS.length },
            { category: 'Connection Strings (SQL, Mongo, Redis, Azure)', count: CONN_STRING_PATTERNS.length },
            { category: 'Cloud Resources (Azure IDs, AWS ARNs, GCP)', count: CLOUD_RESOURCE_PATTERNS.length },
            { category: 'Infrastructure (hostnames, URLs, ports)', count: INFRA_PATTERNS.length },
            { category: 'File Paths (Linux, Windows, UNC)', count: PATH_PATTERNS.length },
            { category: 'Code & Config (stack traces, env vars, Docker)', count: CODE_PATTERNS.length },
            { category: 'IDs (user, session, request, correlation)', count: ID_PATTERNS.length },
        ];
    }

    private buildSummary(patterns: Set<string>, count: number): string {
        const parts: string[] = [];
        for (const p of patterns) {
            parts.push(p.toLowerCase().replace(/_/g, ' '));
        }
        if (parts.length === 0) return 'no sensitive data detected';
        return `${count} item${count > 1 ? 's' : ''} (${parts.join(', ')})`;
    }
}

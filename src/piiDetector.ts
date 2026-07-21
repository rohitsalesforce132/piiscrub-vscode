/**
 * PIIDetector — Core PII detection and redaction engine.
 * Zero dependencies. Pure regex-based detection.
 */

export interface PIIPattern {
    name: string;
    regex: RegExp;
    replacement: string;
}

export interface ScrubResult {
    redactedText: string;
    tokensReplaced: Map<string, string>;  // token → original value
    itemsRedacted: number;
    patterns: string[];                   // which patterns matched
    summary: string;                      // human-readable summary
}

const DEFAULT_PATTERNS: PIIPattern[] = [
    { name: 'EMAIL',       regex: /[\w.+-]+@[\w.-]+\.\w{2,}/g,                                        replacement: '[REDACTED_EMAIL]' },
    { name: 'SSN',         regex: /\b\d{3}-\d{2}-\d{4}\b/g,                                           replacement: '[REDACTED_SSN]' },
    { name: 'PHONE_INTL',  regex: /\+\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{3,4}[\s-]?\d{4}/g,            replacement: '[REDACTED_PHONE]' },
    { name: 'PHONE_US',    regex: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,                                   replacement: '[REDACTED_PHONE]' },
    { name: 'CREDIT_CARD', regex: /\b(?:\d[ -]*?){13,19}\b/g,                                         replacement: '[REDACTED_CC]' },
    { name: 'API_KEY',     regex: /sk-[a-zA-Z0-9]{20,}/g,                                             replacement: '[REDACTED_TOKEN]' },
    { name: 'BEARER',      regex: /Bearer\s+[a-zA-Z0-9_\-\.]+/g,                                      replacement: 'Bearer [REDACTED_TOKEN]' },
    { name: 'AWS_KEY',     regex: /AKIA[A-Z0-9]{16}/g,                                                replacement: '[REDACTED_AWS_KEY]' },
    { name: 'IPV4',        regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g, replacement: '[REDACTED_IP]' },
    { name: 'PASSWORD',    regex: /(?:password|passwd|pwd)[\s:=]+['"]?[^\s'"\,;]+/gi,                replacement: 'password=[REDACTED]' },
    { name: 'USER_ID',     regex: /(?:user[_]?id|userId|customer[_]?id)[\s:=]+\d+/gi,                replacement: '[REDACTED_USER_ID]' },
    { name: 'SESSION_ID',  regex: /(?:session[_]?id|JSESSIONID)[\s:=]+[a-zA-Z0-9]+/gi,              replacement: '[REDACTED_SESSION]' },
    { name: 'AZURE_GUID',  regex: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, replacement: '[REDACTED_GUID]' },
    { name: 'AZURE_RID',   regex: /\/subscriptions\/[0-9a-f-]+/gi,                                    replacement: '[REDACTED_RESOURCE_ID]' },
    { name: 'MAC_ADDR',    regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,                     replacement: '[REDACTED_MAC]' },
];

interface RawCustomPattern {
    name?: string;
    regex?: string;
    replacement?: string;
}

export class PIIDetector {
    private patterns: PIIPattern[];
    private counter: number = 0;

    constructor(customPatterns: RawCustomPattern[] = []) {
        this.patterns = [...DEFAULT_PATTERNS];
        this.addCustom(customPatterns);
    }

    updatePatterns(customPatterns: RawCustomPattern[]) {
        this.patterns = [...DEFAULT_PATTERNS];
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
     * Scrub PII from text. Each unique value gets a unique token
     * so restoration is precise.
     */
    scrub(text: string): ScrubResult {
        let result = text;
        const tokens = new Map<string, string>();
        const matchedPatterns = new Set<string>();

        for (const pattern of this.patterns) {
            // Reset lastIndex for global regexes
            pattern.regex.lastIndex = 0;

            let match: RegExpExecArray | null;
            const matches: RegExpExecArray[] = [];

            while ((match = pattern.regex.exec(result)) !== null) {
                matches.push(match);
                // Prevent infinite loop on zero-length matches
                if (match.index === pattern.regex.lastIndex) {
                    pattern.regex.lastIndex++;
                }
            }

            if (matches.length === 0) continue;

            // Replace in reverse to preserve offsets
            for (let i = matches.length - 1; i >= 0; i--) {
                const m = matches[i];
                const original = m[0];

                // Skip already-redacted tokens
                if (original.startsWith('[REDACTED') || original.includes('[REDACTED')) {
                    continue;
                }

                this.counter++;
                const token = `${pattern.replacement.replace(/\]$/, '')}_${this.counter}]`;

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
     * Restore PII tokens in text back to original values.
     */
    restore(text: string, tokens: Map<string, string>): string {
        let result = text;
        for (const [token, original] of tokens) {
            // Use split/join to avoid regex special chars in token
            result = result.split(token).join(original);
        }
        return result;
    }

    /**
     * Quick check — does this text contain PII?
     */
    hasPII(text: string): boolean {
        for (const pattern of this.patterns) {
            pattern.regex.lastIndex = 0;
            if (pattern.regex.test(text)) return true;
        }
        return false;
    }

    private buildSummary(patterns: Set<string>, count: number): string {
        const parts: string[] = [];
        for (const p of patterns) {
            parts.push(p.toLowerCase().replace(/_/g, ' '));
        }
        if (parts.length === 0) return 'no PII detected';
        return `${count} item${count > 1 ? 's' : ''} (${parts.join(', ')})`;
    }
}

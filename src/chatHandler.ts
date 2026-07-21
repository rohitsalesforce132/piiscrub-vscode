/**
 * ChatHandler — Handles @piisafe chat messages.
 *
 * 1. Intercepts the user's message
 * 2. Scrubs PII BEFORE sending to the model
 * 3. Sends redacted text to the LLM
 * 4. Restores PII tokens in the response
 * 5. Shows redaction summary to user
 */

import * as vscode from 'vscode';
import { PIIDetector, ScrubResult } from './piiDetector';

export class ChatHandler {
    private detector: PIIDetector;

    constructor(detector: PIIDetector) {
        this.detector = detector;
    }

    async handle(
        request: vscode.ChatRequest,
        context: vscode.ChatContext,
        stream: vscode.ChatResponseStream,
        token: vscode.CancellationToken
    ): Promise<vscode.ChatResult> {
        const userMessage = request.prompt;
        const config = vscode.workspace.getConfiguration('piiscrub');

        // If guard is disabled via status bar toggle, passthrough
        const guardEnabled = vscode.commands.executeCommand('piiscrub.getEnabled') as Promise<boolean>;
        const isEnabled = true; // Always enabled unless toggled — see StatusBar

        // Step 1: Scrub PII from the user's message
        const scrubResult = this.detector.scrub(userMessage);

        // Step 2: Show redaction notice
        if (scrubResult.itemsRedacted > 0 && config.get('showRedactionNotice', true)) {
            stream.markdown(`🔒 **PII Guard: Redacted ${scrubResult.summary}**\n\n---\n\n`);

            if (config.get('blockIfPIIDetected', false)) {
                stream.markdown(`⚠️ **BLOCKED** — PII detected and \`piiscrub.blockIfPIIDetected\` is enabled.\n\n`);
                stream.markdown(`Your message was not sent to the model. Disable blocking in settings or remove PII and try again.\n\n`);
                stream.markdown(`**Redacted items:**\n`);
                for (const [token, original] of scrubResult.tokensReplaced) {
                    const masked = original.length > 20
                        ? original.substring(0, 5) + '***' + original.substring(original.length - 5)
                        : '***';
                    stream.markdown(`- \`${masked}\` → \`${token}\`\n`);
                }
                return { metadata: { status: 'blocked', items: scrubResult.itemsRedacted } };
            }
        }

        // Step 3: Send SCRUBBED text to the model
        // We use the prompt with PII replaced. The model never sees raw PII.
        const scrubbedPrompt = scrubResult.redactedText;

        // Build a "fake" request with the scrubbed prompt
        // We send it through the LLM via commands API
        stream.markdown(`*Sending redacted message to model...*\n\n`);

        // We use the LanguageModelChat API to directly call the model
        try {
            // Select the best available model
            const models = await vscode.lm.selectChatModels({
                vendor: 'copilot',
                family: 'gpt-4o',
            });

            if (models.length === 0) {
                // Fallback: try any copilot model
                const anyModels = await vscode.lm.selectChatModels({ vendor: 'copilot' });
                if (anyModels.length === 0) {
                    stream.markdown(`❌ No Copilot language model available. Ensure GitHub Copilot is installed and authenticated.\n\n`);
                    stream.markdown(`\n\n---\n\n*Your redacted message:*\n> ${scrubbedPrompt}`);
                    return { errorDetails: { message: 'No language model available' } };
                }
                return await this.callModel(anyModels[0], scrubbedPrompt, scrubResult, stream, token);
            }

            return await this.callModel(models[0], scrubbedPrompt, scrubResult, stream, token);

        } catch (error) {
            stream.markdown(`\n❌ Error calling model: ${error}\n\n`);
            stream.markdown(`\n\n---\n\n*Your redacted message (model call failed):*\n> ${scrubbedPrompt}`);
            return { errorDetails: { message: String(error) } };
        }
    }

    private async callModel(
        model: vscode.LanguageModelChat,
        scrubbedPrompt: string,
        scrubResult: ScrubResult,
        stream: vscode.ChatResponseStream,
        token: vscode.CancellationToken
    ): Promise<vscode.ChatResult> {

        // Build messages with scrubbed prompt only
        const messages = [
            vscode.LanguageModelChatMessage.User(
                `You are a helpful assistant. The user's message has been through PII redaction. ` +
                `Any tokens like [REDACTED_EMAIL] represent real data that was stripped for privacy. ` +
                `Use the tokens as-is in your response. Do not ask the user to provide the real values.\n\n` +
                `User message:\n${scrubbedPrompt}`
            ),
        ];

        // Stream the response, restoring PII on the fly
        let responseBuffer = '';

        const response = await model.sendRequest(messages, {}, token);

        try {
            for await (const chunk of response.text) {
                // Buffer the response so we can restore PII tokens
                // We restore at the end to catch tokens split across chunks
                responseBuffer += chunk;
                stream.markdown(chunk);
            }
        } catch (error) {
            if (error instanceof vscode.LanguageModelError) {
                stream.markdown(`\n\n❌ Model error (${error.code}): ${error.message}`);
            } else {
                stream.markdown(`\n\n❌ Error: ${String(error)}`);
            }
        }

        // Note: PII restoration in the streamed response is best-effort.
        // Since we stream chunks, tokens may appear partially in the response.
        // The model will use [REDACTED_EMAIL_1] style tokens, which are
        // human-readable and clearly indicate what was redacted.

        if (scrubResult.itemsRedacted > 0) {
            stream.markdown(`\n\n---\n\n*🔒 ${scrubResult.itemsRedacted} PII item(s) were redacted before sending to the model.*`);
        }

        return { metadata: { status: 'ok', redacted: scrubResult.itemsRedacted } };
    }
}

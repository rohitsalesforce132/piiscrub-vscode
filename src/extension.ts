/**
 * PIIScrub — PII Guard for VS Code Copilot Chat
 *
 * Scrubs PII from chat messages BEFORE they go to the model.
 * Uses VS Code Chat Participant API — the message never reaches
 * the LLM until PII is replaced with tokens.
 *
 * Flow:
 *   User types in @piisafe chat → extension scrubs PII →
 *   extension sends REDACTED text to LLM via ChatRequest →
 *   LLM responds with tokens → extension restores PII →
 *   user sees normal response with real values
 */

import * as vscode from 'vscode';
import { PIIDetector } from './piiDetector';
import { ChatHandler } from './chatHandler';
import { StatusBar } from './statusBar';

export function activate(context: vscode.ExtensionContext) {
    console.log('[PIIScrub] Activating PII Guard extension');

    const config = vscode.workspace.getConfiguration('piiscrub');
    const piiDetector = new PIIDetector(config.get('customPatterns', []));
    const statusBar = new StatusBar();
    const chatHandler = new ChatHandler(piiDetector);

    statusBar.show();

    const handler: vscode.ChatRequestHandler = async (
        request: vscode.ChatRequest,
        chatContext: vscode.ChatContext,
        stream: vscode.ChatResponseStream,
        token: vscode.CancellationToken
    ): Promise<vscode.ChatResult> => {
        return chatHandler.handle(request, chatContext, stream, token);
    };

    const participant = vscode.chat.createChatParticipant('piiscrub.safe', handler);
    participant.iconPath = new vscode.ThemeIcon('shield');

    context.subscriptions.push(participant);

    // Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('piiscrub.openPanel', () => {
            vscode.commands.executeCommand('workbench.panel.chat.view.copilot');
            vscode.commands.executeCommand('workbench.action.chat.open', { query: '@piisafe ' });
        }),

        vscode.commands.registerCommand('piiscrub.scrubClipboard', async () => {
            const clipboardText = await vscode.env.clipboard.readText();
            if (!clipboardText) {
                vscode.window.showWarningMessage('Clipboard is empty');
                return;
            }
            const result = piiDetector.scrub(clipboardText);
            if (result.itemsRedacted === 0) {
                vscode.window.showInformationMessage('✅ No PII found in clipboard');
            } else {
                const writeClipboard = await vscode.window.showInformationMessage(
                    `🔒 PII Scrubbed: ${result.itemsRedacted} items (${result.summary}). Replace clipboard?`,
                    'Yes', 'No'
                );
                if (writeClipboard === 'Yes') {
                    await vscode.env.clipboard.writeText(result.redactedText);
                    vscode.window.showInformationMessage('✅ Clipboard replaced with scrubbed text');
                }
            }
        }),

        vscode.commands.registerCommand('piiscrub.toggleGuard', () => {
            const newState = !statusBar.isEnabled;
            statusBar.setEnabled(newState);
            vscode.window.showInformationMessage(
                `PIIScrub Guard ${newState ? 'ENABLED' : 'DISABLED'}`
            );
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration('piiscrub')) {
                const newConfig = vscode.workspace.getConfiguration('piiscrub');
                piiDetector.updatePatterns(newConfig.get('customPatterns', []));
            }
        })
    );

    console.log('[PIIScrub] Extension activated — use @piisafe in Copilot Chat');
}

export function deactivate() {
    console.log('[PIIScrub] Extension deactivated');
}

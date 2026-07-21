/**
 * StatusBar — Shows PIIScrub guard status in the VS Code status bar.
 * Click to toggle the guard on/off.
 */

import * as vscode from 'vscode';

export class StatusBar {
    private item: vscode.StatusBarItem;
    public isEnabled: boolean = true;

    constructor() {
        this.item = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            100
        );
        this.item.command = 'piiscrub.toggleGuard';
        this.update();
    }

    show() {
        this.item.show();
    }

    setEnabled(enabled: boolean) {
        this.isEnabled = enabled;
        this.update();
    }

    private update() {
        if (this.isEnabled) {
            this.item.text = '$(shield) PII Guard';
            this.item.backgroundColor = new vscode.ThemeColor(
                'statusBarItem.warningBackground'
            );
            this.item.tooltip = 'PIIScrub Active — PII is scrubbed before reaching the model. Click to disable.';
        } else {
            this.item.text = '$(shield) PII Off';
            this.item.backgroundColor = undefined;
            this.item.tooltip = 'PIIScrub Disabled — raw messages sent to model. Click to enable.';
        }
    }

    dispose() {
        this.item.dispose();
    }
}

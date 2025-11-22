import { Injectable } from '@angular/core';

declare const window: any;

const electronAPI = typeof window !== 'undefined' ? window.electronAPI : undefined;

@Injectable({
  providedIn: 'root'
})
export class ShellService {
  private readonly storageKey = 'paranoid_auto_launch';

  async getAutoLaunch(): Promise<boolean> {
    if (electronAPI?.invoke) {
      try {
        return Boolean(await electronAPI.invoke('app:auto-launch:get'));
      } catch {
        // fall back
      }
    }
    const stored = localStorage.getItem(this.storageKey);
    return stored === null ? true : stored === 'true';
  }

  async setAutoLaunch(enabled: boolean): Promise<void> {
    if (electronAPI?.invoke) {
      await electronAPI.invoke('app:auto-launch:set', !!enabled);
    } else {
      localStorage.setItem(this.storageKey, String(Boolean(enabled)));
    }
  }
}

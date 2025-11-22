import { Injectable, NgZone } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

declare const window: any;

export interface ClientProfile {
  fullName: string;
  organization: string;
  email: string;
  phone?: string;
  persona?: string;
  alertingLevel: 'quiet' | 'concierge' | 'full';
  darkwebKeywords: string[];
  darkwebHost?: string;
  darkwebPath?: string;
  darkwebServicePort?: number;
  torProxyPort?: number;
  usbDeviceHint?: string;
  usbWorkdir?: string;
  autoLaunch?: boolean;
  profileId?: string;
  notes?: string;
  createdAt?: string;
  updatedAt?: string;
}

const electronAPI = typeof window !== 'undefined' ? window.electronAPI : undefined;

@Injectable({
  providedIn: 'root'
})
export class ProfileService {
  private readonly storageKey = 'paranoid_profile_fallback';
  private readonly profileSubject = new BehaviorSubject<ClientProfile | null>(null);
  readonly profile$ = this.profileSubject.asObservable();
  private currentProfile: ClientProfile | null = null;

  constructor(private zone: NgZone) {
    this.bootstrap();
  }

  async save(profile: ClientProfile): Promise<void> {
    const payload: ClientProfile = {
      ...profile,
      darkwebKeywords: (profile.darkwebKeywords || []).map((keyword) => keyword.trim()).filter(Boolean),
      createdAt: profile.createdAt ?? new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    try {
      if (electronAPI) {
        await electronAPI.invoke('profile:save', payload);
      } else {
        this.persistFallback(payload);
      }
      this.zone.run(() => this.profileSubject.next(payload));
    } catch (error) {
      this.persistFallback(payload);
      this.zone.run(() => this.profileSubject.next(payload));
      throw error;
    }
  }

  private async bootstrap(): Promise<void> {
    if (electronAPI) {
      try {
        const response = await electronAPI.invoke('profile:load');
        if (response) {
          this.zone.run(() => this.updateProfile(response as ClientProfile));
          return;
        }
      } catch {
        // fall back to local storage below
      }
    }
    const fallback = this.readFallback();
    this.updateProfile(
      fallback ?? {
        fullName: '',
        organization: '',
        email: '',
        alertingLevel: 'concierge',
        darkwebKeywords: [],
        darkwebHost: '',
        darkwebPath: '/search',
        darkwebServicePort: 80,
        torProxyPort: 9050,
        autoLaunch: true
      }
    );
  }

  getCurrentProfile(): ClientProfile | null {
    return this.currentProfile;
  }

  private updateProfile(profile: ClientProfile): void {
    const enriched: ClientProfile = {
      profileId: profile.profileId ?? this.deriveProfileId(),
      darkwebPath: profile.darkwebPath ?? '/search',
      darkwebServicePort: profile.darkwebServicePort ?? 80,
      torProxyPort: profile.torProxyPort ?? 9050,
      autoLaunch: profile.autoLaunch ?? true,
      ...profile
    };
    this.currentProfile = enriched;
    this.profileSubject.next(enriched);
  }

  private persistFallback(profile: ClientProfile): void {
    try {
      localStorage.setItem(this.storageKey, JSON.stringify(profile));
    } catch {
      /* ignore */
    }
  }

  private readFallback(): ClientProfile | null {
    try {
      const stored = localStorage.getItem(this.storageKey);
      return stored ? (JSON.parse(stored) as ClientProfile) : null;
    } catch {
      return null;
    }
  }

  private deriveProfileId(): string {
    try {
      return `${navigator?.platform ?? 'paranoid'}-${navigator?.language ?? 'en-US'}`;
    } catch {
      return 'paranoid-profile';
    }
  }
}

import { Injectable, NgZone } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

declare const window: any;

export interface SubscriptionPlan {
  licenseKey: string;
  plan: string;
  seats: number;
  owner: string;
  contactEmail: string;
  expiresAt: string;
  status: 'active' | 'expired' | 'trial';
}

const electronAPI = typeof window !== 'undefined' ? window.electronAPI : undefined;

@Injectable({
  providedIn: 'root'
})
export class SubscriptionService {
  private readonly storageKey = 'paranoid_subscription_fallback';
  private readonly subject = new BehaviorSubject<SubscriptionPlan | null>(null);
  readonly subscription$ = this.subject.asObservable();

  constructor(private zone: NgZone) {
    this.bootstrap();
  }

  async save(plan: SubscriptionPlan): Promise<void> {
    const payload = { ...plan };
    if (electronAPI) {
      await electronAPI.invoke('subscription:save', payload);
    } else {
      this.persistFallback(payload);
    }
    this.zone.run(() => this.subject.next(payload));
  }

  private async bootstrap(): Promise<void> {
    if (electronAPI) {
      try {
        const response = await electronAPI.invoke('subscription:load');
        if (response) {
          this.zone.run(() => this.subject.next(response as SubscriptionPlan));
          return;
        }
      } catch {
        // fall through to fallback
      }
    }
    const fallback = this.readFallback();
    this.subject.next(
      fallback ?? {
        licenseKey: 'UNREGISTERED',
        plan: 'Trial',
        seats: 1,
        owner: 'Local Device',
        contactEmail: 'support@paranoidlabs.local',
        expiresAt: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
        status: 'trial'
      }
    );
  }

  private persistFallback(plan: SubscriptionPlan): void {
    try {
      localStorage.setItem(this.storageKey, JSON.stringify(plan));
    } catch {
      /* ignore */
    }
  }

  private readFallback(): SubscriptionPlan | null {
    try {
      const raw = localStorage.getItem(this.storageKey);
      return raw ? (JSON.parse(raw) as SubscriptionPlan) : null;
    } catch {
      return null;
    }
  }
}

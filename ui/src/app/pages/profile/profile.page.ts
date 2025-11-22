import { Component, OnDestroy } from '@angular/core';
import { FormArray, FormBuilder, Validators } from '@angular/forms';
import { Subscription } from 'rxjs';
import { ClientProfile, ProfileService } from '../../services/profile.service';
import { ShellService } from '../../services/shell.service';

interface StatusBanner {
  tone: 'success' | 'danger';
  message: string;
}

@Component({
  selector: 'app-profile',
  templateUrl: './profile.page.html',
  styleUrls: ['./profile.page.scss']
})
export class ProfilePage implements OnDestroy {
  readonly form = this.buildForm();

  status?: StatusBanner;
  private currentProfile: ClientProfile | null = null;
  private subscription = new Subscription();

  constructor(
    private fb: FormBuilder,
    private profileService: ProfileService,
    private shellService: ShellService
  ) {
    this.subscription.add(
      this.profileService.profile$.subscribe((profile) => {
        this.currentProfile = profile;
        if (profile) {
          this.populate(profile);
        }
      })
    );
    if (this.keywords.length === 0) {
      this.addKeyword();
    }
    this.shellService.getAutoLaunch().then((enabled) => {
      this.form.patchValue({ autoLaunch: enabled });
    });
  }

  ngOnDestroy(): void {
    this.subscription.unsubscribe();
  }

  get keywords(): FormArray {
    return this.form.get('darkwebKeywords') as FormArray;
  }

  private buildForm() {
    return this.fb.group({
      fullName: ['', Validators.required],
      organization: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]],
      phone: [''],
      persona: [''],
      alertingLevel: ['concierge', Validators.required],
      darkwebHost: [''],
      darkwebPath: ['/search'],
      darkwebServicePort: [80, Validators.min(1)],
      torProxyPort: [9050, Validators.min(1)],
      usbDeviceHint: [''],
      usbWorkdir: [''],
      autoLaunch: [true],
      darkwebKeywords: this.fb.array<string>([])
    });
  }

  addKeyword(value = ''): void {
    this.keywords.push(this.fb.control(value));
  }

  removeKeyword(index: number): void {
    this.keywords.removeAt(index);
    if (this.keywords.length === 0) {
      this.addKeyword();
    }
  }

  async save(): Promise<void> {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      this.status = { tone: 'danger', message: 'Please complete the highlighted fields.' };
      return;
    }
    const payload: ClientProfile = {
      ...(this.currentProfile ?? {}),
      ...(this.form.value as ClientProfile)
    };
    payload.darkwebKeywords = this.keywords.value.map((keyword: string) => keyword?.trim()).filter(Boolean);
    payload.darkwebServicePort = Number(payload.darkwebServicePort ?? 80);
    payload.torProxyPort = Number(payload.torProxyPort ?? 9050);
    payload.autoLaunch = Boolean(this.form.value.autoLaunch);
    try {
      await this.profileService.save(payload);
      await this.shellService.setAutoLaunch(payload.autoLaunch ?? true);
      this.status = { tone: 'success', message: 'Profile sealed inside the quantum-safe vault.' };
    } catch (error) {
      this.status = { tone: 'danger', message: (error as Error).message ?? 'Failed to persist profile.' };
    }
  }

  private populate(profile: ClientProfile): void {
    this.form.patchValue({
      fullName: profile.fullName ?? '',
      organization: profile.organization ?? '',
      email: profile.email ?? '',
      phone: profile.phone ?? '',
      persona: profile.persona ?? '',
      alertingLevel: profile.alertingLevel ?? 'concierge',
      darkwebHost: profile.darkwebHost ?? '',
      darkwebPath: profile.darkwebPath ?? '/search',
      darkwebServicePort: profile.darkwebServicePort ?? 80,
      torProxyPort: profile.torProxyPort ?? 9050,
      usbDeviceHint: profile.usbDeviceHint ?? '',
      usbWorkdir: profile.usbWorkdir ?? '',
      autoLaunch: profile.autoLaunch ?? this.form.value.autoLaunch
    });
    this.keywords.clear();
    (profile.darkwebKeywords ?? []).forEach((keyword) => this.addKeyword(keyword));
    if (this.keywords.length === 0) {
      this.addKeyword();
    }
  }
}

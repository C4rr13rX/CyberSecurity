import { Component, OnDestroy } from '@angular/core';
import { NavigationEnd, Router } from '@angular/router';
import { Subscription } from 'rxjs';
import { BackendService } from '../services/backend.service';
import { ClientProfile, ProfileService } from '../services/profile.service';
import { SubscriptionPlan, SubscriptionService } from '../services/subscription.service';

interface SectionModule {
  id: string;
  title: string;
  description: string;
  cta: string;
  icon: string;
  action: 'command' | 'route';
  command?: string;
  route?: string;
}

interface CommandSection {
  id: string;
  label: string;
  description: string;
  icon: string;
  route: string;
  modules: SectionModule[];
}

interface MetricGauge {
  id: string;
  label: string;
  icon: string;
  value: number;
  prefix?: string;
  suffix?: string;
}

@Component({
  selector: 'app-tabs',
  templateUrl: 'tabs.page.html',
  styleUrls: ['tabs.page.scss']
})
export class TabsPage implements OnDestroy {
  readonly sections: CommandSection[] = [
    {
      id: 'dashboard',
      label: 'Mission Control',
      description: 'Live situational awareness & risk telemetry.',
      icon: 'grid-outline',
      route: 'dashboard',
      modules: [
        {
          id: 'ops-snapshot',
          title: 'Process Snapshot',
          description: 'Capture running processes with heuristics and threat-intel enrichment.',
          cta: 'Snapshot now',
          icon: 'pulse-outline',
          action: 'command',
          command: 'runProcessSnapshot'
        },
        {
          id: 'ops-audit',
          title: 'System Audit',
          description: 'Collect host hygiene findings, misconfigurations, and hardening gaps.',
          cta: 'Audit host',
          icon: 'clipboard-outline',
          action: 'command',
          command: 'runSystemAudit'
        },
        {
          id: 'ops-rootkit',
          title: 'Rootkit Sweep',
          description: 'Invoke deep kernel inspection routines to surface stealth implants.',
          cta: 'Sweep kernel',
          icon: 'bug-outline',
          action: 'command',
          command: 'runRootkitScan'
        }
      ]
    },
    {
      id: 'processes',
      label: 'Process Intelligence',
      description: 'Investigate processes, heuristics, and response actions.',
      icon: 'pulse-outline',
      route: 'processes',
      modules: [
        {
          id: 'ops-quarantine',
          title: 'Immediate Containment',
          description: 'Use CLI responders to kill or isolate suspicious PIDs with evidence.',
          cta: 'View console',
          icon: 'shield-half-outline',
          action: 'route',
          route: 'processes'
        }
      ]
    },
    {
      id: 'integrity',
      label: 'File Integrity',
      description: 'Baseline sensitive paths and verify tamper-resistant chains.',
      icon: 'layers-outline',
      route: 'integrity',
      modules: [
        {
          id: 'integrity-baseline',
          title: 'Baseline Critical Paths',
          description: 'Capture a golden baseline for system32, LSA plug-ins, and startup folders.',
          cta: 'Open integrity lab',
          icon: 'finger-print-outline',
          action: 'route',
          route: 'integrity'
        }
      ]
    },
    {
      id: 'intel',
      label: 'Threat Intel',
      description: 'Synchronise signatures, YARA packs, and intel bundles.',
      icon: 'analytics-outline',
      route: 'intel',
      modules: [
        {
          id: 'intel-refresh-now',
          title: 'Reload Intel Packs',
          description: 'Push curated malware signatures, IOC feeds, and AI models.',
          cta: 'Refresh intel',
          icon: 'cloud-download-outline',
          action: 'command',
          command: 'runThreatIntelReload'
        },
        {
          id: 'intel-console',
          title: 'Intel Workbench',
          description: 'Manage YARA packs, AI scoring models, and IOA bundles.',
          cta: 'Open intel desk',
          icon: 'analytics-outline',
          action: 'route',
          route: 'intel'
        }
      ]
    },
    {
      id: 'darkweb',
      label: 'Dark Web Recon',
      description: 'Search onions, credential dumps, and leak forums.',
      icon: 'planet-outline',
      route: 'darkweb',
      modules: [
        {
          id: 'darkweb-search',
          title: 'Single Recon Run',
          description: 'Launch an immediate sweep using saved keywords and personas.',
          cta: 'Recon now',
          icon: 'search-outline',
          action: 'command',
          command: 'runDarkwebSearch'
        },
        {
          id: 'darkweb-stream',
          title: 'Continuous Detection',
          description: 'Keep Tor monitors running with live detections and notifications.',
          cta: 'Start stream',
          icon: 'radio-outline',
          action: 'command',
          command: 'startDarkwebStream'
        },
        {
          id: 'darkweb-stream-stop',
          title: 'Stop Streaming Jobs',
          description: 'Gracefully shutdown looping recon jobs if they are running.',
          cta: 'Stop stream',
          icon: 'pause-outline',
          action: 'command',
          command: 'stopStreaming'
        }
      ]
    },
    {
      id: 'firewall',
      label: 'Adaptive Firewall',
      description: 'Manage Windows firewall, merge policies, and enforce segments.',
      icon: 'shield-checkmark-outline',
      route: 'firewall',
      modules: [
        {
          id: 'firewall-refresh',
          title: 'Inventory Policies',
          description: 'Refresh WSC products, firewall rules, and enforcement posture.',
          cta: 'Refresh status',
          icon: 'shield-outline',
          action: 'command',
          command: 'refreshFirewallStatus'
        },
        {
          id: 'firewall-console',
          title: 'Policy Workbench',
          description: 'Load, save, and edit firewall baselines and application rules.',
          cta: 'Open firewall desk',
          icon: 'options-outline',
          action: 'route',
          route: 'firewall'
        }
      ]
    },
    {
      id: 'system',
      label: 'System Repair',
      description: 'Manifest-driven file repair, Windows audits, and USB deployers.',
      icon: 'construct-outline',
      route: 'system',
      modules: [
        {
          id: 'system-audit',
          title: 'Repair Plan',
          description: 'Generate a manifest-driven repair plan before shipping field kit.',
          cta: 'Audit now',
          icon: 'hammer-outline',
          action: 'command',
          command: 'auditWindowsRepair'
        },
        {
          id: 'system-detect',
          title: 'Detect Windows Version',
          description: 'Collect build, SKU, and manifest hints for remote guidance.',
          cta: 'Detect version',
          icon: 'desktop-outline',
          action: 'command',
          command: 'detectWindowsVersion'
        },
        {
          id: 'system-usb',
          title: 'USB Sensor Builder',
          description: 'Provision a hardened USB scanner with Tor client and CLI sensor.',
          cta: 'Deploy USB',
          icon: 'hardware-chip-outline',
          action: 'command',
          command: 'deployUsbScanner'
        }
      ]
    },
    {
      id: 'profile',
      label: 'Client Profile',
      description: 'Identity, white-label tone, and subscription preferences.',
      icon: 'person-circle-outline',
      route: 'profile',
      modules: [
        {
          id: 'profile-open',
          title: 'Identity & Preferences',
          description: 'Capture contact channels, keywords, and service posture for automation.',
          cta: 'Edit profile',
          icon: 'create-outline',
          action: 'route',
          route: 'profile'
        }
      ]
    }
  ];

  activeSection: CommandSection = this.sections[0];
  moduleBusy: Record<string, boolean> = {};
  commandFeed: { timestamp: Date; message: string }[] = [];
  gauges: MetricGauge[] = [
    { id: 'processes', label: 'Tracked Processes', icon: 'pulse-outline', value: 0 },
    { id: 'findings', label: 'System Findings', icon: 'warning-outline', value: 0 },
    { id: 'darkweb', label: 'Dark Web Hits', icon: 'planet-outline', value: 0 }
  ];

  private subscription = new Subscription();
  subscriptionPlan: SubscriptionPlan | null = null;
  private currentProfile: ClientProfile | null = null;

  constructor(
    private router: Router,
    private backend: BackendService,
    private profileService: ProfileService,
    private subscriptionService: SubscriptionService
  ) {
    this.subscription.add(
      this.router.events.subscribe((event) => {
        if (event instanceof NavigationEnd) {
          this.syncSection(event.urlAfterRedirects);
        }
      })
    );
    this.subscription.add(
      this.backend.processes$.subscribe((list) => {
        this.updateGauge('processes', list.length);
      })
    );
    this.subscription.add(
      this.backend.systemFindings$.subscribe((list) => {
        this.updateGauge('findings', list.length);
      })
    );
    this.subscription.add(
      this.backend.darkwebHits$.subscribe((list) => {
        this.updateGauge('darkweb', list.length);
      })
    );
    this.subscription.add(
      this.profileService.profile$.subscribe((profile) => (this.currentProfile = profile))
    );
    this.subscription.add(
      this.subscriptionService.subscription$.subscribe((plan) => (this.subscriptionPlan = plan))
    );
    this.syncSection(this.router.url || '/dashboard');
  }

  ngOnDestroy(): void {
    this.subscription.unsubscribe();
  }

  goTo(section: CommandSection): void {
    this.router.navigate(['/', section.route]);
  }

  async activateModule(module: SectionModule): Promise<void> {
    if (module.action === 'route' && module.route) {
      this.router.navigate(['/', module.route]);
      return;
    }
    if (!module.command) {
      return;
    }
    try {
      this.moduleBusy[module.id] = true;
      await this.executeCommand(module.command);
      this.pushCommandFeed(`${module.title} executed`);
    } catch (error) {
      this.pushCommandFeed(`${module.title} failed: ${(error as Error).message}`);
    } finally {
      this.moduleBusy[module.id] = false;
    }
  }

  private async executeCommand(command: string): Promise<void> {
    switch (command) {
      case 'runProcessSnapshot':
        await this.backend.runProcessSnapshot(true);
        break;
      case 'runSystemAudit':
        await this.backend.runSystemAudit();
        break;
      case 'runRootkitScan':
        await this.backend.runRootkitScan();
        break;
      case 'runDarkwebSearch':
        await this.backend.runDarkwebSearch(this.buildDarkwebSearchRequest());
        break;
      case 'startDarkwebStream':
        await this.backend.startDarkwebStream(this.buildDarkwebStreamRequest());
        break;
      case 'stopStreaming':
        await this.backend.stopStreaming();
        break;
      case 'runThreatIntelReload':
        await this.backend.runThreatIntelReload(this.currentProfile?.usbWorkdir ?? 'auto');
        break;
      case 'refreshFirewallStatus':
        await this.backend.refreshFirewallStatus();
        break;
      case 'auditWindowsRepair':
        await this.backend.auditWindowsRepair({ manifest: 'default', windowsRoot: undefined });
        break;
      case 'detectWindowsVersion':
        await this.backend.detectWindowsVersion();
        break;
      case 'deployUsbScanner':
        await this.deployUsbScanner();
        break;
      default:
        break;
    }
  }

  private updateGauge(id: string, value: number): void {
    const gauge = this.gauges.find((g) => g.id === id);
    if (gauge) {
      gauge.value = value;
    }
  }

  private pushCommandFeed(message: string): void {
    this.commandFeed.unshift({ timestamp: new Date(), message });
    this.commandFeed = this.commandFeed.slice(0, 4);
  }

  private syncSection(url: string): void {
    const clean = url.replace(/^\//, '');
    const match = this.sections.find((section) => clean.startsWith(section.route));
    this.activeSection = match ?? this.sections[0];
  }

  private buildDarkwebSearchRequest() {
    const profile = this.currentProfile;
    return {
      host: profile?.darkwebHost || 'exampleonion.onion',
      path: profile?.darkwebPath || '/search',
      port: profile?.darkwebServicePort || 80,
      proxy: profile?.torProxyPort || 9050,
      keywords: profile?.darkwebKeywords?.length ? profile.darkwebKeywords : ['security', 'compromise']
    };
  }

  private buildDarkwebStreamRequest() {
    const payload = this.buildDarkwebSearchRequest();
    return {
      host: payload.host,
      path: payload.path,
      port: payload.port,
      proxy: payload.proxy,
      keywords: payload.keywords,
      cadenceMinutes: 30
    };
  }

  private async deployUsbScanner(): Promise<void> {
    const device = this.currentProfile?.usbDeviceHint?.trim();
    if (!device) {
      throw new Error('Set a USB device hint in the profile first.');
    }
    await this.backend.deployUsbScanner({
      device,
      workdir: this.currentProfile?.usbWorkdir,
      includeTor: true
    });
  }
}

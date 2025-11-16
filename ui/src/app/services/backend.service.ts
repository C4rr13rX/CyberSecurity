import { Injectable, NgZone } from '@angular/core';
import { BehaviorSubject, Observable, Subject } from 'rxjs';

export interface StreamEvent {
  channel: string;
  payload: unknown;
}

export interface ProcessSummary {
  pid: number;
  name: string;
  user: string;
  riskScore: number;
  heuristics: { weight: number; description: string; reference?: string }[];
  exePath?: string;
  threatIntelHits?: string[];
}

export interface SystemFinding {
  id: string;
  severity: 'low' | 'medium' | 'high';
  description: string;
  remediation?: string;
}

export interface RootkitFinding {
  id: string;
  indicator: string;
  description: string;
  severity: number;
  evidence?: string;
  remediation?: string;
}

export interface DarkwebHit {
  keyword: string;
  matchType: string;
  confidence: number;
  lineNumber?: number;
  context: string;
  source?: string;
}

export interface WindowsVersionInfo {
  productName: string;
  manifestKey: string;
  build: string;
  success?: boolean;
}

export interface WindowsRepairIssue {
  type: 'missing' | 'mismatch';
  path: string;
  critical: boolean;
  expectedHash: string;
  expectedSize: number;
  observedHash?: string;
  observedSize?: number;
}

export interface WindowsRepairPlanSummary {
  version: string;
  build: string;
  manifestKey: string;
  windowsRoot: string;
  issues: WindowsRepairIssue[];
  errors: string[];
  planPath?: { path: string; saved: boolean };
}

export interface WindowsRepairStageSummary {
  success: boolean;
  copied: string[];
  missingSources: string[];
  errors: string[];
}

interface ElectronAPI {
  invoke: (channel: string, ...args: any[]) => Promise<any>;
  startStream: (name: string, args?: Record<string, any>) => Promise<string>;
  stopStream: (token: string) => Promise<void>;
  onStream: (listener: (event: StreamEvent) => void) => () => void;
}

const electronAPI: ElectronAPI | undefined = (window as any)['electronAPI'];

@Injectable()
export class BackendService {
  private logSubject = new Subject<string>();
  readonly log$: Observable<string> = this.logSubject.asObservable();

  private processSubject = new BehaviorSubject<ProcessSummary[]>([]);
  readonly processes$ = this.processSubject.asObservable();

  private darkwebHits = new BehaviorSubject<DarkwebHit[]>([]);
  readonly darkwebHits$ = this.darkwebHits.asObservable();

  private systemFindings = new BehaviorSubject<SystemFinding[]>([]);
  readonly systemFindings$ = this.systemFindings.asObservable();

  private rootkitFindings = new BehaviorSubject<RootkitFinding[]>([]);
  readonly rootkitFindings$ = this.rootkitFindings.asObservable();

  private windowsVersion = new BehaviorSubject<WindowsVersionInfo | null>(null);
  readonly windowsVersion$ = this.windowsVersion.asObservable();

  private windowsPlan = new BehaviorSubject<WindowsRepairPlanSummary | null>(null);
  readonly windowsPlan$ = this.windowsPlan.asObservable();

  private windowsStage = new BehaviorSubject<WindowsRepairStageSummary | null>(null);
  readonly windowsStage$ = this.windowsStage.asObservable();

  private activeStreamToken?: string;
  private removeListener?: () => void;

  constructor(private zone: NgZone) {
    if (electronAPI) {
      this.removeListener = electronAPI.onStream((event: StreamEvent) => {
        this.zone.run(() => this.handleStream(event));
      });
    }
  }

  async runProcessSnapshot(detailed = false): Promise<void> {
    const response = await this.invoke('command:monitor', { detailed });
    if (response?.processes) {
      this.processSubject.next(response.processes);
    }
    this.emitLog(response?.log ?? 'Process snapshot complete.');
  }

  async runSystemAudit(): Promise<void> {
    const response = await this.invoke('command:system-audit');
    if (response?.findings) {
      this.systemFindings.next(response.findings);
    }
    this.emitLog(response?.log ?? 'System audit complete.');
  }

  async runRootkitScan(): Promise<void> {
    const response = await this.invoke('command:rootkit-scan');
    if (response?.findings) {
      const mapped = (response.findings as any[]).map((finding) => ({
        id: finding.id,
        indicator: finding.indicator,
        description: finding.description,
        severity: Number(finding.severity ?? 0),
        evidence: finding.evidence,
        remediation: finding.remediation
      }));
      this.rootkitFindings.next(mapped);
    }
    this.emitLog(response?.log ?? 'Rootkit sweep complete.');
  }

  async runFileIntegrity(action: 'baseline' | 'verify', path: string, snapshot: string): Promise<void> {
    const response = await this.invoke('command:file-integrity', { action, path, snapshot });
    this.emitLog(response?.log ?? `Integrity ${action} finished.`);
  }

  async runThreatIntelReload(path: string): Promise<void> {
    const response = await this.invoke('command:threat-intel', { path });
    this.emitLog(response?.log ?? 'Threat intelligence updated.');
  }

  async runSignatureScan(target: string, options: { withYara?: boolean; yaraRules?: string } = {}): Promise<void> {
    const response = await this.invoke('command:signature-scan', {
      target,
      withYara: options.withYara,
      yaraRules: options.yaraRules
    });
    this.emitLog(response?.log ?? 'Signature scan complete.');
  }

  async runQuarantine(action: 'kill' | 'file', value: string): Promise<void> {
    const response = await this.invoke('command:quarantine', { action, value });
    this.emitLog(response?.log ?? 'Quarantine action complete.');
  }

  async runDarkwebSearch(request: {
    host: string;
    path: string;
    port?: number;
    proxy?: number;
    keywords: string[];
  }): Promise<void> {
    const response = await this.invoke('command:darkweb-search', request);
    if (response?.hits) {
      const existing = this.darkwebHits.value || [];
      const combined = [...existing, ...(response.hits as DarkwebHit[])];
      this.darkwebHits.next(combined.slice(-100));
    }
    this.emitLog(response?.log ?? 'Dark web lookup triggered.');
  }

  async deployUsbScanner(request: { device: string; workdir?: string; includeTor?: boolean }): Promise<void> {
    const response = await this.invoke('command:usb-build', request);
    this.emitLog(response?.log ?? 'USB build triggered.');
  }

  async detectWindowsVersion(): Promise<void> {
    const response = await this.invoke('command:windows-detect');
    const info = response?.info as any;
    if (info) {
      const summary: WindowsVersionInfo = {
        productName: info.productName ?? '',
        manifestKey: info.manifestKey ?? '',
        build: info.build ?? '',
        success: info.success !== false
      };
      this.windowsVersion.next(summary);
    }
    this.emitLog(response?.log ?? 'Windows version detection attempted.');
  }

  async auditWindowsRepair(request: { manifest: string; windowsRoot?: string; planPath?: string }): Promise<void> {
    const response = await this.invoke('command:windows-audit', request);
    if (response?.plan) {
      const plan = response.plan as any;
      const summary: WindowsRepairPlanSummary = {
        version: plan.version ?? '',
        build: plan.build ?? '',
        manifestKey: plan.manifestKey ?? '',
        windowsRoot: plan.windowsRoot ?? '',
        issues: Array.isArray(plan.issues)
          ? plan.issues.map((issue: any) => ({
              type: (issue.type as 'missing' | 'mismatch') ?? 'missing',
              path: issue.path ?? '',
              critical: Boolean(issue.critical),
              expectedHash: issue.expectedHash ?? '',
              expectedSize: Number(issue.expectedSize ?? 0),
              observedHash: issue.observedHash ?? undefined,
              observedSize: issue.observedSize !== undefined ? Number(issue.observedSize) : undefined
            }))
          : [],
        errors: Array.isArray(plan.errors) ? plan.errors : [],
        planPath: response.planPath
          ? { path: response.planPath.path ?? '', saved: Boolean(response.planPath.saved) }
          : undefined
      };
      this.windowsPlan.next(summary);
    } else {
      this.windowsPlan.next(null);
    }
    this.windowsStage.next(null);
    this.emitLog(response?.log ?? 'Windows repair audit complete.');
  }

  async collectWindowsRepairs(request: {
    repository: string;
    output: string;
    manifest?: string;
    windowsRoot?: string;
  }): Promise<void> {
    const response = await this.invoke('command:windows-collect', request);
    if (response?.plan) {
      const plan = response.plan as any;
      const summary: WindowsRepairPlanSummary = {
        version: plan.version ?? '',
        build: plan.build ?? '',
        manifestKey: plan.manifestKey ?? '',
        windowsRoot: plan.windowsRoot ?? '',
        issues: Array.isArray(plan.issues)
          ? plan.issues.map((issue: any) => ({
              type: (issue.type as 'missing' | 'mismatch') ?? 'missing',
              path: issue.path ?? '',
              critical: Boolean(issue.critical),
              expectedHash: issue.expectedHash ?? '',
              expectedSize: Number(issue.expectedSize ?? 0),
              observedHash: issue.observedHash ?? undefined,
              observedSize: issue.observedSize !== undefined ? Number(issue.observedSize) : undefined
            }))
          : [],
        errors: Array.isArray(plan.errors) ? plan.errors : [],
        planPath: response.planPath
          ? { path: response.planPath.path ?? '', saved: Boolean(response.planPath.saved) }
          : undefined
      };
      this.windowsPlan.next(summary);
    } else {
      this.windowsPlan.next(null);
    }
    if (response?.stage) {
      const stage = response.stage as any;
      const stageSummary: WindowsRepairStageSummary = {
        success: Boolean(stage.success),
        copied: Array.isArray(stage.copied) ? stage.copied : [],
        missingSources: Array.isArray(stage.missingSources) ? stage.missingSources : [],
        errors: Array.isArray(stage.errors) ? stage.errors : []
      };
      this.windowsStage.next(stageSummary);
    } else {
      this.windowsStage.next(null);
    }
    this.emitLog(response?.log ?? 'Windows repair staging complete.');
  }

  async startContinuousMonitoring(intervalSeconds: number): Promise<void> {
    if (!electronAPI) {
      return;
    }
    await this.stopStreaming();
    this.activeStreamToken = await electronAPI.startStream('monitor-loop', { intervalSeconds });
  }

  async startDarkwebStream(config: {
    host: string;
    path: string;
    port?: number;
    proxy?: number;
    keywords: string[];
    cadenceMinutes: number;
  }): Promise<void> {
    if (!electronAPI) {
      return;
    }
    await this.stopStreaming();
    this.activeStreamToken = await electronAPI.startStream('darkweb-loop', config);
  }

  async stopStreaming(): Promise<void> {
    if (!electronAPI || !this.activeStreamToken) {
      return;
    }
    await electronAPI.stopStream(this.activeStreamToken);
    this.activeStreamToken = undefined;
  }

  ngOnDestroy(): void {
    this.stopStreaming();
    this.removeListener?.();
  }

  private handleStream(event: StreamEvent): void {
    switch (event.channel) {
      case 'log':
        this.emitLog(String(event.payload ?? ''));
        break;
      case 'process-update':
        this.processSubject.next(event.payload as ProcessSummary[]);
        break;
      case 'darkweb-hit':
        const hits = this.darkwebHits.value || [];
        const combinedStream = [...hits, ...(event.payload as DarkwebHit[])];
        this.darkwebHits.next(combinedStream.slice(-100));
        break;
      case 'system-update':
        this.systemFindings.next(event.payload as SystemFinding[]);
        break;
      default:
        this.emitLog(`(stream:${event.channel}) ${JSON.stringify(event.payload)}`);
    }
  }

  private async invoke(channel: string, payload?: Record<string, any>): Promise<any> {
    if (!electronAPI) {
      this.emitLog('Electron bridge unavailable; running in browser preview mode.');
      return undefined;
    }
    try {
      return await electronAPI.invoke(channel, payload);
    } catch (error: any) {
      this.emitLog(`${channel} failed: ${error?.message ?? error}`);
      throw error;
    }
  }

  private emitLog(message: string): void {
    const entry = `[${new Date().toISOString()}] ${message}`;
    this.logSubject.next(entry);
  }
}

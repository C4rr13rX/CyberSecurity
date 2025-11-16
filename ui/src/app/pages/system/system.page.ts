import { Component, OnDestroy, OnInit } from '@angular/core';
import { Subscription } from 'rxjs';
import {
  BackendService,
  RootkitFinding,
  SystemFinding,
  WindowsRepairPlanSummary,
  WindowsRepairStageSummary,
  WindowsVersionInfo
} from '../../services/backend.service';

@Component({
  selector: 'app-system',
  templateUrl: './system.page.html',
  styleUrls: ['./system.page.scss']
})
export class SystemPage implements OnInit, OnDestroy {
  findings: SystemFinding[] = [];
  rootkit: RootkitFinding[] = [];
  logs: string[] = [];
  usbDevice = '';
  usbWorkdir = '';
  usbIncludeTor = false;

  windowsManifest = '';
  windowsPlanPath = '';
  windowsRoot = '';
  windowsRepository = '';
  windowsOutput = '';
  windowsManifestOverride = '';

  windowsVersion?: WindowsVersionInfo | null;
  windowsPlan?: WindowsRepairPlanSummary | null;
  windowsStage?: WindowsRepairStageSummary | null;

  private subs: Subscription[] = [];

  constructor(private backend: BackendService) {}

  ngOnInit(): void {
    this.subs.push(
      this.backend.systemFindings$.subscribe((findings) => (this.findings = findings)),
      this.backend.rootkitFindings$.subscribe((findings) => (this.rootkit = findings)),
      this.backend.windowsVersion$.subscribe((info) => (this.windowsVersion = info)),
      this.backend.windowsPlan$.subscribe((plan) => (this.windowsPlan = plan)),
      this.backend.windowsStage$.subscribe((stage) => (this.windowsStage = stage)),
      this.backend.log$.subscribe((entry) => (this.logs = [...this.logs.slice(-199), entry]))
    );
  }

  ngOnDestroy(): void {
    this.subs.forEach((sub) => sub.unsubscribe());
  }

  async audit(): Promise<void> {
    await this.backend.runSystemAudit();
  }

  async rootkitScan(): Promise<void> {
    await this.backend.runRootkitScan();
  }

  async buildUsb(): Promise<void> {
    if (!this.usbDevice.trim()) {
      this.appendLog('USB build requires a device path (e.g., /dev/sdb).');
      return;
    }
    await this.backend.deployUsbScanner({
      device: this.usbDevice.trim(),
      workdir: this.usbWorkdir.trim() || undefined,
      includeTor: this.usbIncludeTor
    });
  }

  async detectWindows(): Promise<void> {
    await this.backend.detectWindowsVersion();
  }

  async auditWindows(): Promise<void> {
    if (!this.windowsManifest.trim()) {
      this.appendLog('Provide a manifest file before auditing Windows baselines.');
      return;
    }
    await this.backend.auditWindowsRepair({
      manifest: this.windowsManifest.trim(),
      windowsRoot: this.windowsRoot.trim() || undefined,
      planPath: this.windowsPlanPath.trim() || undefined
    });
  }

  async collectWindows(): Promise<void> {
    if (!this.windowsRepository.trim() || !this.windowsOutput.trim()) {
      this.appendLog('Windows repair collection requires repository and output directories.');
      return;
    }
    await this.backend.collectWindowsRepairs({
      repository: this.windowsRepository.trim(),
      output: this.windowsOutput.trim(),
      manifest: this.windowsManifestOverride.trim() || undefined,
      windowsRoot: this.windowsRoot.trim() || undefined
    });
  }

  private appendLog(message: string): void {
    const entry = `[${new Date().toISOString()}] ${message}`;
    this.logs = [...this.logs.slice(-199), entry];
  }
}

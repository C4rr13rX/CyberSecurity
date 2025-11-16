import { Component, OnDestroy, OnInit } from '@angular/core';
import { Subscription } from 'rxjs';
import { BackendService, ProcessSummary, SystemFinding } from '../../services/backend.service';

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.page.html',
  styleUrls: ['./dashboard.page.scss']
})
export class DashboardPage implements OnInit, OnDestroy {
  processes: ProcessSummary[] = [];
  findings: SystemFinding[] = [];
  logs: string[] = [];

  private subs: Subscription[] = [];

  constructor(private backend: BackendService) {}

  ngOnInit(): void {
    this.subs.push(
      this.backend.processes$.subscribe((processes) => (this.processes = processes)),
      this.backend.systemFindings$.subscribe((findings) => (this.findings = findings)),
      this.backend.log$.subscribe((entry) => this.logs = [...this.logs.slice(-199), entry])
    );
  }

  ngOnDestroy(): void {
    this.subs.forEach((sub) => sub.unsubscribe());
  }

  async refreshAll(): Promise<void> {
    await Promise.all([this.backend.runProcessSnapshot(), this.backend.runSystemAudit()]);
  }

  topProcesses(): ProcessSummary[] {
    return this.processes
      .slice()
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, 5);
  }

  topFindings(): SystemFinding[] {
    return this.findings.slice(0, 5);
  }
}

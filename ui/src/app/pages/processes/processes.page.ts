import { Component, OnDestroy, OnInit } from '@angular/core';
import { Subscription } from 'rxjs';
import { BackendService, ProcessSummary } from '../../services/backend.service';

@Component({
  selector: 'app-processes',
  templateUrl: './processes.page.html',
  styleUrls: ['./processes.page.scss']
})
export class ProcessesPage implements OnInit, OnDestroy {
  processes: ProcessSummary[] = [];
  filtered: ProcessSummary[] = [];
  search = '';
  logs: string[] = [];

  interval = 10;
  streaming = false;

  private subs: Subscription[] = [];

  constructor(private backend: BackendService) {}

  ngOnInit(): void {
    this.subs.push(
      this.backend.processes$.subscribe((processes) => {
        this.processes = processes;
        this.applyFilter();
      }),
      this.backend.log$.subscribe((entry) => (this.logs = [...this.logs.slice(-199), entry]))
    );
  }

  ngOnDestroy(): void {
    this.subs.forEach((sub) => sub.unsubscribe());
    this.stopLoop();
  }

  applyFilter(): void {
    const term = this.search.toLowerCase();
    this.filtered = this.processes.filter((proc) =>
      [proc.name, proc.user, String(proc.pid)].some((value) => (value || '').toLowerCase().includes(term))
    );
  }

  async snapshot(): Promise<void> {
    await this.backend.runProcessSnapshot(true);
  }

  async startLoop(): Promise<void> {
    this.streaming = true;
    await this.backend.startContinuousMonitoring(this.interval);
  }

  async stopLoop(): Promise<void> {
    this.streaming = false;
    await this.backend.stopStreaming();
  }

  riskBadge(score: number): string {
    if (score >= 70) {
      return 'risk-high';
    }
    if (score >= 40) {
      return 'risk-medium';
    }
    return 'risk-low';
  }
}

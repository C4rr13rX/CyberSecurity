import { Component, OnDestroy, OnInit } from '@angular/core';
import { Subscription } from 'rxjs';
import { BackendService, DarkwebHit } from '../../services/backend.service';

@Component({
  selector: 'app-dark-web',
  templateUrl: './dark-web.page.html',
  styleUrls: ['./dark-web.page.scss']
})
export class DarkWebPage implements OnInit, OnDestroy {
  keywords = 'firstname lastname, email@example.com';
  cadence = 30;
  streaming = false;
  host = 'exampleonion.onion';
  path = '/search';
  port = 80;
  proxy = 9050;

  hits: DarkwebHit[] = [];
  logs: string[] = [];

  private subs: Subscription[] = [];

  constructor(private backend: BackendService) {}

  ngOnInit(): void {
    this.subs.push(
      this.backend.darkwebHits$.subscribe((hits) => (this.hits = [...(hits as DarkwebHit[])].reverse())),
      this.backend.log$.subscribe((entry) => (this.logs = [...this.logs.slice(-199), entry]))
    );
  }

  ngOnDestroy(): void {
    this.subs.forEach((sub) => sub.unsubscribe());
    this.stopStream();
  }

  async searchNow(): Promise<void> {
    const list = this.keywords.split(',').map((kw) => kw.trim()).filter((kw) => kw.length > 0);
    if (!this.host || !this.path || list.length === 0) {
      return;
    }
    await this.backend.runDarkwebSearch({
      host: this.host,
      path: this.path,
      port: Number(this.port) || undefined,
      proxy: Number(this.proxy) || undefined,
      keywords: list
    });
  }

  async startStream(): Promise<void> {
    const list = this.keywords.split(',').map((kw) => kw.trim()).filter((kw) => kw.length > 0);
    if (!this.host || !this.path || list.length === 0) {
      return;
    }
    await this.backend.startDarkwebStream({
      host: this.host,
      path: this.path,
      port: Number(this.port) || undefined,
      proxy: Number(this.proxy) || undefined,
      keywords: list,
      cadenceMinutes: this.cadence
    });
    this.streaming = true;
  }

  async stopStream(): Promise<void> {
    await this.backend.stopStreaming();
    this.streaming = false;
  }
}

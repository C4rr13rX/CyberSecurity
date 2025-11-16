import { Component } from '@angular/core';
import { BackendService } from '../../services/backend.service';

@Component({
  selector: 'app-threat-intel',
  templateUrl: './threat-intel.page.html',
  styleUrls: ['./threat-intel.page.scss']
})
export class ThreatIntelPage {
  indicatorPath = 'indicators.csv';
  scanTarget = '/var/tmp/sample';
  yara = false;
  yaraRules = 'rules/index.yar';
  quarantineValue = '';
  quarantineMode: 'kill' | 'file' = 'file';

  constructor(private backend: BackendService) {}

  async reloadIntel(): Promise<void> {
    await this.backend.runThreatIntelReload(this.indicatorPath);
  }

  async scan(): Promise<void> {
    await this.backend.runSignatureScan(this.scanTarget, {
      withYara: this.yara,
      yaraRules: this.yaraRules
    });
  }

  async quarantine(): Promise<void> {
    if (!this.quarantineValue) {
      return;
    }
    await this.backend.runQuarantine(this.quarantineMode, this.quarantineValue);
    this.quarantineValue = '';
  }
}

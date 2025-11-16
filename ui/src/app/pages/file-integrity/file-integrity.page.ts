import { Component } from '@angular/core';
import { BackendService } from '../../services/backend.service';

@Component({
  selector: 'app-file-integrity',
  templateUrl: './file-integrity.page.html',
  styleUrls: ['./file-integrity.page.scss']
})
export class FileIntegrityPage {
  target = '/etc';
  snapshot = '/var/lib/paranoid/etc.baseline';

  constructor(private backend: BackendService) {}

  async baseline(): Promise<void> {
    await this.backend.runFileIntegrity('baseline', this.target, this.snapshot);
  }

  async verify(): Promise<void> {
    await this.backend.runFileIntegrity('verify', this.target, this.snapshot);
  }
}

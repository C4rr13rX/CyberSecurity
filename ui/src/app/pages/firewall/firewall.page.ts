import { Component, OnInit } from '@angular/core';
import { BackendService, FirewallStatus, SecurityCenterProduct } from '../../services/backend.service';
import { Observable } from 'rxjs';

@Component({
  selector: 'app-firewall',
  templateUrl: './firewall.page.html',
  styleUrls: ['./firewall.page.scss']
})
export class FirewallPage implements OnInit {
  firewallStatus$: Observable<FirewallStatus | null> = this.backend.firewallStatus$;
  securityProducts$: Observable<SecurityCenterProduct[]> = this.backend.securityCenterProducts$;

  appRule = { path: '', label: '', direction: 'both' };
  portRule = { port: '', protocol: 'TCP', direction: 'both', label: '' };
  policyPath = '';
  registerForm = { name: '', path: '', reporting: '', mode: 'both', guid: '' };

  constructor(private backend: BackendService) {}

  async ngOnInit(): Promise<void> {
    await this.refreshAll();
  }

  async ionViewWillEnter(): Promise<void> {
    await this.refreshAll();
  }

  async refreshAll(): Promise<void> {
    await Promise.all([this.backend.refreshFirewallStatus(), this.backend.refreshSecurityCenterStatus()]);
  }

  async refreshFirewall(): Promise<void> {
    await this.backend.refreshFirewallStatus();
  }

  async refreshSecurityCenter(): Promise<void> {
    await this.backend.refreshSecurityCenterStatus();
  }

  async addApplicationRule(): Promise<void> {
    const path = this.appRule.path.trim();
    if (!path) {
      return;
    }
    await this.backend.addFirewallApplication({
      path,
      label: this.appRule.label.trim() || undefined,
      direction: this.appRule.direction
    });
    this.appRule = { path: '', label: '', direction: this.appRule.direction };
  }

  async addPortRule(): Promise<void> {
    const port = Number(this.portRule.port);
    if (!port || port <= 0) {
      return;
    }
    await this.backend.addFirewallPort({
      port,
      protocol: this.portRule.protocol,
      direction: this.portRule.direction,
      label: this.portRule.label.trim() || undefined
    });
    this.portRule = { ...this.portRule, port: '', label: '' };
  }

  async loadPolicy(): Promise<void> {
    const path = this.policyPath.trim();
    if (!path) {
      return;
    }
    await this.backend.loadFirewallPolicy(path);
  }

  async savePolicy(): Promise<void> {
    const path = this.policyPath.trim();
    if (!path) {
      return;
    }
    await this.backend.saveFirewallPolicy(path);
  }

  async removeRule(name?: string): Promise<void> {
    const trimmed = (name ?? '').trim();
    if (!trimmed) {
      return;
    }
    await this.backend.removeFirewallRule(trimmed);
  }

  async registerSecuritySuite(): Promise<void> {
    const name = this.registerForm.name.trim();
    const path = this.registerForm.path.trim();
    if (!name || !path) {
      return;
    }
    await this.backend.registerSecurityCenter({
      name,
      path,
      reporting: this.registerForm.reporting.trim() || undefined,
      guid: this.registerForm.guid.trim() || undefined,
      mode: this.registerForm.mode
    });
  }
}

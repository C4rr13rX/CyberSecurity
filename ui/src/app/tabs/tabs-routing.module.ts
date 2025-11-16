import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

import { TabsPage } from './tabs.page';

const routes: Routes = [
  {
    path: '',
    component: TabsPage,
    children: [
      {
        path: 'dashboard',
        loadChildren: () => import('../pages/dashboard/dashboard.module').then((m) => m.DashboardPageModule)
      },
      {
        path: 'processes',
        loadChildren: () => import('../pages/processes/processes.module').then((m) => m.ProcessesPageModule)
      },
      {
        path: 'integrity',
        loadChildren: () => import('../pages/file-integrity/file-integrity.module').then((m) => m.FileIntegrityPageModule)
      },
      {
        path: 'intel',
        loadChildren: () => import('../pages/threat-intel/threat-intel.module').then((m) => m.ThreatIntelPageModule)
      },
      {
        path: 'darkweb',
        loadChildren: () => import('../pages/dark-web/dark-web.module').then((m) => m.DarkWebPageModule)
      },
      {
        path: 'firewall',
        loadChildren: () => import('../pages/firewall/firewall.module').then((m) => m.FirewallPageModule)
      },
      {
        path: 'system',
        loadChildren: () => import('../pages/system/system.module').then((m) => m.SystemPageModule)
      },
      {
        path: '',
        redirectTo: 'dashboard',
        pathMatch: 'full'
      }
    ]
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class TabsPageRoutingModule {}

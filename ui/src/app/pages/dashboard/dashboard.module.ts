import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { IonicModule } from '@ionic/angular';
import { RouterModule } from '@angular/router';

import { DashboardPage } from './dashboard.page';
import { SharedModule } from '../../shared/shared.module';

@NgModule({
  imports: [CommonModule, IonicModule, SharedModule, RouterModule.forChild([{ path: '', component: DashboardPage }])],
  declarations: [DashboardPage]
})
export class DashboardPageModule {}

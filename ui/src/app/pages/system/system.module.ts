import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { IonicModule } from '@ionic/angular';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';

import { SystemPage } from './system.page';
import { SharedModule } from '../../shared/shared.module';

@NgModule({
  imports: [CommonModule, IonicModule, FormsModule, SharedModule, RouterModule.forChild([{ path: '', component: SystemPage }])],
  declarations: [SystemPage]
})
export class SystemPageModule {}

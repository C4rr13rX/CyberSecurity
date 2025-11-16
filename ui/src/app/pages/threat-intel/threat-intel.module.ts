import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { IonicModule } from '@ionic/angular';
import { RouterModule } from '@angular/router';

import { ThreatIntelPage } from './threat-intel.page';

@NgModule({
  imports: [CommonModule, FormsModule, IonicModule, RouterModule.forChild([{ path: '', component: ThreatIntelPage }])],
  declarations: [ThreatIntelPage]
})
export class ThreatIntelPageModule {}

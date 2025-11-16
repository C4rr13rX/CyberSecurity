import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { IonicModule } from '@ionic/angular';

import { LogStreamComponent } from './components/log-stream/log-stream.component';

@NgModule({
  declarations: [LogStreamComponent],
  imports: [CommonModule, IonicModule],
  exports: [LogStreamComponent]
})
export class SharedModule {}

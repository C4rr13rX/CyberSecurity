import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { IonicModule } from '@ionic/angular';
import { RouterModule } from '@angular/router';

import { FileIntegrityPage } from './file-integrity.page';

@NgModule({
  imports: [CommonModule, FormsModule, IonicModule, RouterModule.forChild([{ path: '', component: FileIntegrityPage }])],
  declarations: [FileIntegrityPage]
})
export class FileIntegrityPageModule {}

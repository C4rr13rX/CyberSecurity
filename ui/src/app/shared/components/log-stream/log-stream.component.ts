import { Component, Input } from '@angular/core';

@Component({
  selector: 'app-log-stream',
  templateUrl: './log-stream.component.html',
  styleUrls: ['./log-stream.component.scss']
})
export class LogStreamComponent {
  @Input() entries: string[] = [];
}

import { PipeTransform, Injectable, Inject } from '@nestjs/common';
import { LoggingTool } from '../tools/logging/logging.tool';

@Injectable()
export class LoggingPipe implements PipeTransform {
  constructor(@Inject(LoggingTool) private loggingTool: LoggingTool) {
    this.loggingTool.setContext(LoggingPipe.name);
  }

  transform(value: any) {
    this.loggingTool.verbose(value);

    return value;
  }
}

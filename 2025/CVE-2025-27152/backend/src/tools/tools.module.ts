import { Global, Module } from '@nestjs/common';
import { LoggingTool } from './logging/logging.tool';

@Global()
@Module({
  providers: [LoggingTool],
  exports: [LoggingTool],
})
export class ToolsModule {}

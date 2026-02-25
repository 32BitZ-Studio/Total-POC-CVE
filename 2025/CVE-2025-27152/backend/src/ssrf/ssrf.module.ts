import { Module } from '@nestjs/common';
import { SsrfController } from './ssrf.controller';
import { SsrfService } from './ssrf.service';
import { LoggingTool } from '../tools/logging/logging.tool';

@Module({
  controllers: [SsrfController],
  providers: [SsrfService, LoggingTool],
})
export class SsrfModule {}

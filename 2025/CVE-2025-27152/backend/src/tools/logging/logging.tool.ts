import { Injectable, Logger, LoggerService, Scope } from '@nestjs/common';

@Injectable({ scope: Scope.TRANSIENT })
export class LoggingTool implements LoggerService {
  private logger = new Logger();

  public setContext(context: string) {
    this.logger = new Logger(context);
  }

  public debug(message: string, extras?: Record<string, unknown>) {
    this.logger.debug(message, ...(extras ? [extras] : []));
  }

  public error(error: unknown, extras?: Record<string, unknown>) {
    this.logger.error(error, ...(extras ? [extras] : []));
  }

  public log(message: string, extras?: Record<string, unknown>) {
    this.logger.log(message, ...(extras ? [extras] : []));
  }

  public warn(message: string, extras?: Record<string, unknown>) {
    this.logger.warn(message, ...(extras ? [extras] : []));
  }

  public verbose(message: string, extras?: Record<string, unknown>) {
    this.logger.verbose(message, ...(extras ? [extras] : []));
  }
}

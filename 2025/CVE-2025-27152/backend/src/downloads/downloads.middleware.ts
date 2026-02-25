import {
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  NestMiddleware,
} from '@nestjs/common';
import { Request, Response } from 'express';
import * as path from 'path';
import { LoggingTool } from '../tools/logging/logging.tool';

@Injectable()
export class DownloadsAccessMiddleware implements NestMiddleware {
  constructor(@Inject(LoggingTool) private loggingTool: LoggingTool) {
    this.loggingTool.setContext(DownloadsAccessMiddleware.name);
  }

  use(req: Request, res: Response) {
    if (!req.baseUrl || !req.params.param?.length) {
      this.throwInvalidException(
        `Intercepting download: could not read download file parameters`,
      );
    }

    const baseUrl = req.baseUrl;
    const params = req.params.param;

    let folderName: string | undefined;
    let fileName: string;

    if (params.length > 1) {
      folderName = params[0];
      fileName = params[1];
    } else {
      fileName = params[0];
    }

    const path = folderName ? `${folderName}/${fileName}` : fileName;

    this.loggingTool.debug(
      `Intercepting call to ${baseUrl} and download path ${path}`,
    );

    if (DownloadsAccessMiddleware.isNickDownload(baseUrl)) {
      this.loggingTool.debug(
        `Intercepting download request for a Nicolas Cage image`,
      );
      const filePath = './src/downloads/assets/' + path;
      const authorized = true;
      if (!authorized) {
        this.throwInvalidException(
          'User is not authorized to access Nicolas Cage files',
        );
      }
      this.loggingTool.debug(`Nicolas Cage download ${filePath} granted`);
      return res.download(filePath);
    }

    if (DownloadsAccessMiddleware.isLindaDownload(baseUrl)) {
      this.loggingTool.debug(`Intercepting download request for a Linda image`);
      const filePath = './src/downloads/assets/' + path;
      const authorized = true;
      if (!authorized) {
        this.throwInvalidException('User is not authorized to access the file');
      }
      this.loggingTool.debug(`Linda download ${filePath} granted`);
      // provide download
      return res.download(filePath);
    }

    this.throwInvalidException(
      `Intercepting unknown download request  - deny access`,
    );
  }

  private throwInvalidException(errorMessage: string): void {
    this.loggingTool.warn(errorMessage);
    throw new HttpException(
      {
        code: 'NOT_AUTHORIZED_TO_ACCESS_FILE',
        message: 'User is not authorized to access the file',
      },
      HttpStatus.FORBIDDEN,
    );
  }

  private static isNickDownload(url: string): boolean {
    return url
      .replace(/[^a-zA-Z]/g, '')
      .startsWith(
        path.join('api', `/downloads/nick`).replace(/[^a-zA-Z]/g, ''),
      );
  }

  private static isLindaDownload(url: string): boolean {
    return url
      .replace(/[^a-zA-Z]/g, '')
      .startsWith(
        path.join('api', `/downloads/linda`).replace(/[^a-zA-Z]/g, ''),
      );
  }
}

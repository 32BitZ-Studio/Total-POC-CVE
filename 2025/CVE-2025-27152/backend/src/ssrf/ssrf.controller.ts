import { Controller, Post, Inject, Body } from '@nestjs/common';
import { SsrfService } from './ssrf.service';
import { LoggingTool } from '../tools/logging/logging.tool';
import { GetMoviesBySearchDto } from './get-movies-by-search.dto';

@Controller('search')
export class SsrfController {
  constructor(
    private readonly ssrfService: SsrfService,
    @Inject(LoggingTool) private readonly loggingTool: LoggingTool,
  ) {
    this.loggingTool.setContext(SsrfController.name);
  }

  @Post()
  getMoviesBySearch(@Body() body: GetMoviesBySearchDto) {
    this.loggingTool.debug(`Called search`);
    return this.ssrfService.getMoviesBySearch(body);
  }
}

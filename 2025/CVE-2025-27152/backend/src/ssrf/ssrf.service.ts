import { Inject, Injectable } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import { LoggingTool } from '../tools/logging/logging.tool';
import { GetMoviesBySearchDto } from './get-movies-by-search.dto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class SsrfService {
  private ROOT_URL: string;
  private internalAPIClient: AxiosInstance;

  constructor(
    private configService: ConfigService,
    @Inject(LoggingTool) private readonly loggingTool: LoggingTool,
  ) {
    this.loggingTool.setContext(SsrfService.name);
    const api_key = this.configService.get<string>('TMDB_API_KEY');
    this.ROOT_URL = `https://api.themoviedb.org/3/search/movie?api_key=${api_key}&language=en-US&&include_adult=false&query=`;
    this.internalAPIClient = axios.create({
      baseURL: this.ROOT_URL,
      headers: {
        'X-SECRET':
          'congratulations you found the secret password: turned-abode-scull-joey',
      },
    });
  }

  async getMoviesBySearch(body: GetMoviesBySearchDto) {
    this.loggingTool.log(`Getting movies by search word: ${body.searchWord}`);

    if (body.pageNumber) {
      return (
        await this.internalAPIClient.get(
          `${body.searchWord}&page=${body.pageNumber}`,
        )
      ).data;
    }
    return (await this.internalAPIClient.get(`${body.searchWord}`)).data;
  }
}

import { Inject, Injectable } from '@nestjs/common';
import axios from 'axios';
import { LoggingTool } from '../tools/logging/logging.tool';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MoviesService {
  private apiKeyParameter: string;
  private TRENDING_URL: string;

  constructor(
    private configService: ConfigService,
    @Inject(LoggingTool) private readonly loggingTool: LoggingTool,
  ) {
    this.loggingTool.setContext(MoviesService.name);
    this.apiKeyParameter =
      'api_key=' + this.configService.get<string>('TMDB_API_KEY');
    this.TRENDING_URL = `trending/movie/week?${this.apiKeyParameter}`;
  }

  private ROOT_URL = 'https://api.themoviedb.org/3';
  private MOVIE_URL = `movie/`;

  private internalAPIClient = axios.create({
    baseURL: this.ROOT_URL,
  });

  async getMovies(): Promise<string> {
    this.loggingTool.log(`Getting movies without page`);

    return (await this.internalAPIClient.get(`${this.TRENDING_URL}`)).data;
  }

  async getTrendingMoviesByPage(page: string) {
    this.loggingTool.log(`Getting movies by page: ${page}`);

    return (
      await this.internalAPIClient.get(`${this.TRENDING_URL}&page=${page}`)
    ).data;
  }

  async getMovieDetailsById(id: string) {
    return (
      await this.internalAPIClient.get(
        `${this.MOVIE_URL}${id}?language=en-US&${this.apiKeyParameter}`,
      )
    ).data;
  }

  async getMovieCastById(id: string) {
    return (
      await this.internalAPIClient.get(
        `${this.MOVIE_URL}${id}/credits?language=en-US&${this.apiKeyParameter}`,
      )
    ).data;
  }
}

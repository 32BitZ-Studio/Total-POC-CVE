import { Controller, Get, Inject, Param } from '@nestjs/common';
import { MoviesService } from './movies.service';
import { LoggingTool } from '../tools/logging/logging.tool';
import { MoviesActions } from './movies.actions';

@Controller('movies')
export class MoviesController {
  constructor(
    private readonly moviesService: MoviesService,
    @Inject(LoggingTool) private readonly loggingTool: LoggingTool,
  ) {
    this.loggingTool.setContext(MoviesController.name);
  }
  @Get()
  getMovies(): Promise<string> {
    return this.moviesService.getMovies();
  }

  @Get(':page')
  getTrendingMoviesByPage(@Param('page') page: string) {
    return this.moviesService.getTrendingMoviesByPage(page);
  }

  @Get(MoviesActions.GET_MOVIE_DETAILS + ':id')
  getMovieDetailsById(@Param('id') id: string) {
    return this.moviesService.getMovieDetailsById(id);
  }
  @Get(MoviesActions.GET_MOVIE_CAST + ':id')
  getMovieCastById(@Param('id') id: string) {
    return this.moviesService.getMovieCastById(id);
  }
}

import { Injectable } from '@angular/core';
import { WebRequestService } from './services/web-request.service';

@Injectable({
  providedIn: 'root',
})
export class TaskService {
  constructor(private webRequestService: WebRequestService) {}

  getApiMovieDetails(id: string) {
    return this.webRequestService.getFromApi('movies/movie/' + id);
  }

  getApiMovieCast(id: string) {
    return this.webRequestService.getFromApi('movies/cast/' + id);
  }

  getApiMovies(path: string) {
    return this.webRequestService.getFromApi('movies/' + path);
  }

  getApiMoviesBySearchWord(searchWord: string) {
    return this.webRequestService.postToApi('search/', { searchWord });
  }

  getApiMoviesBySearchWordAndPage(searchWord: string, pageNumber: number) {
    return this.webRequestService.postToApi('search/', {
      searchWord,
      pageNumber,
    });
  }
}

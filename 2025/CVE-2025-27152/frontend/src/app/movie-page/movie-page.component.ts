import { Component, OnInit } from '@angular/core';
import {
  HashLocationStrategy,
  Location,
  LocationStrategy,
} from '@angular/common';
import { Movie } from '../movie-list/movie-list.component';
import { TaskService } from '../task.service';

export class Person {
  constructor(
    public adult: boolean,
    public caast_id: number,
    public character: string,
    public credit_id: string,
    public gender: number,
    public id: number,
    public known_for_department: string,
    public name: string,
    public order: number,
    public original_name: string,
    public popularity: number,
    public profile_path: string | null,
  ) {}
}

@Component({
  selector: 'app-movie-page',
  templateUrl: './movie-page.component.html',
  styleUrls: ['./movie-page.component.scss'],
  providers: [
    Location,
    { provide: LocationStrategy, useClass: HashLocationStrategy },
  ],
})
export class MoviePageComponent implements OnInit {
  movieId: string;
  movie: Movie;
  cast: Person[];
  localStorage = JSON.parse(localStorage.getItem('watchList') || '[]');
  constructor(
    location: Location,
    private taskService: TaskService,
  ) {
    this.movieId = location.path().split('#')[1];
  }

  ngOnInit(): void {
    this.getMovieDetails();
  }

  getMovieDetails() {
    this.taskService
      .getApiMovieDetails(this.movieId)
      .subscribe((response: any) => (this.movie = response));
    this.taskService
      .getApiMovieCast(this.movieId)
      .subscribe((response: any) => {
        if (response.cast) {
          response.cast.sort((a: any, b: any) => {
            if (a.profile_path === null && b.profile_path !== 'null') {
              return 1;
            }
            if (a.profile_path !== 'null' && b.profile_path === null) {
              return -1;
            } else {
              return 0;
            }
          });
        }
        this.cast = response.cast;
      });
  }

  addToWatchList() {
    // Check if localStorage is empty
    if (this.localStorage.length !== 0) {
      // Check if movie is already in the watchList:
      for (const movie of this.localStorage) {
        if (movie.title === this.movie.title) {
          return;
        }
      }
    }
    this.localStorage.push(this.movie);
    localStorage.setItem('watchList', JSON.stringify(this.localStorage));
  }
}

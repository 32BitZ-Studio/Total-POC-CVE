import { Component, OnInit } from '@angular/core';
import { TaskService } from '../task.service';
import { Router } from '@angular/router';
import { Location } from '@angular/common';

export class Movie {
  constructor(
    public adult: boolean,
    public backdrop_path: string | null,
    public belongs_to_collection: null | object,
    public budget: number,
    public genre_ids: number[],
    public homepage: string | null,
    public id: number,
    public imdb_id: string | null,
    public original_language: string,
    public original_title: string,
    public overview: string | null,
    public popularity: number,
    public poster_path: string | null,
    public production_companies: {
      name: string;
      id: number;
      logo_path: string | null;
      origin_country: string;
    }[],
    public production_countries: { iso_3166_1: string; name: string },
    public release_date: string,
    public revenue: number,
    public runtime: number | null,
    public spoken_languages: { iso_639_1: string; name: string },
    public status: string,
    public tagline: string | null,
    public title: string,
    public video: boolean,
    public vote_average: number,
    public vote_count: number,
  ) {}
}

@Component({
  selector: 'app-movie-list',
  templateUrl: './movie-list.component.html',
  styleUrls: ['./movie-list.component.scss'],
})
export class MovieListComponent implements OnInit {
  movieList: Movie[];
  public currentPage: number = 1;
  public total: number;

  constructor(
    private taskService: TaskService,
    private location: Location,
    private router: Router,
  ) {
    if (location.path().split('#')[1]) {
      // Get current page
      this.currentPage = parseInt(location.path().split('#')[1]);
    }
  }

  ngOnInit() {
    this.createNewList();
  }

  createNewList() {
    this.taskService
      .getApiMovies(`${this.currentPage}`)
      .subscribe((response: any) => {
        this.total = response.total_pages;
        this.movieList = response.results;
        /* this.movieList.sort((a, b) => { // Order by release date
          if (a.release_date > b.release_date) {
            return -1;
          } else {
            return 1;
          }
        }); */
      });
  }

  public onGoTo(page: number): void {
    this.currentPage = page;
  }

  public onNext(page: number): void {
    this.currentPage = page + 1;
    this.router.navigate([], { fragment: `${this.currentPage}` });
    this.taskService
      .getApiMovies(`${this.currentPage}`)
      .subscribe((response: any) => {
        this.movieList = response.results;
      });
  }

  public onPrevious(page: number): void {
    this.currentPage = page - 1;
    this.router.navigate([], { fragment: `${this.currentPage}` });
    this.taskService
      .getApiMovies(`${this.currentPage}`)
      .subscribe((response: any) => {
        this.movieList = response.results;
      });
  }
}

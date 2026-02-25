import { Component, OnInit } from '@angular/core';
import { NgForm } from '@angular/forms';

import { Movie } from '../movie-list/movie-list.component';
import { TaskService } from '../task.service';
import { Router } from '@angular/router';
import { Location } from '@angular/common';

@Component({
  selector: 'app-search',
  templateUrl: './search.component.html',
  styleUrls: ['./search.component.scss'],
})
export class SearchComponent implements OnInit {
  searchItem: string = '';
  movieList: Movie[];
  public current: number = 1;
  public total: number;

  constructor(
    private taskService: TaskService,
    private location: Location,
    private router: Router,
  ) {
    if (this.location.path().split('#')[1]) {
      // Get current searched item
      this.searchItem = this.location.path().split('#')[1];
      if (location.path().split('#')[2]) {
        // Get current searched page
        this.current = parseInt(this.location.path().split('#')[2]);
      }
      this.getSearch();
    }
  }

  getSearch() {
    this.taskService
      .getApiMoviesBySearchWord(`${this.searchItem}`)
      .subscribe((response: any) => {
        this.total = response.total_pages;
        this.movieList = response.results;
      });
  }

  onSubmit(form: NgForm) {
    // Add search term and page in the #route
    this.router.navigate([], {
      fragment: `${this.searchItem}#${this.current}`,
    });
    this.getSearch();
  }

  ngOnInit(): void {}

  public onGoTo(page: number): void {
    this.current = page;
  }

  public onNext(page: number): void {
    this.current = page + 1;
    this.router.navigate([], {
      fragment: `${this.searchItem}#${this.current}`,
    });
    this.taskService
      .getApiMoviesBySearchWordAndPage(this.searchItem, this.current)
      .subscribe((response: any) => {
        this.movieList = response.results;
      });
  }

  public onPrevious(page: number): void {
    this.current = page - 1;
    this.router.navigate([], {
      fragment: `${this.searchItem}#${this.current}`,
    });
    this.taskService
      .getApiMoviesBySearchWordAndPage(this.searchItem, this.current)
      .subscribe((response: any) => {
        this.movieList = response.results;
      });
  }
}

import { Component, OnInit } from '@angular/core';
import { Movie } from '../movie-list/movie-list.component';

@Component({
  selector: 'app-watch-list',
  templateUrl: './watch-list.component.html',
  styleUrls: ['./watch-list.component.scss'],
})
export class WatchListComponent implements OnInit {
  movieList = JSON.parse(localStorage.getItem('watchList') || '[]');

  constructor() {}

  ngOnInit(): void {}

  removeFromWatchList(item: Movie) {
    const index = this.movieList.indexOf(item);
    this.movieList.splice(index, 1);
    localStorage.setItem('watchList', JSON.stringify(this.movieList));
  }
}

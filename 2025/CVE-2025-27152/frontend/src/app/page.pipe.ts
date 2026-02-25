import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'page',
})
export class PagePipe implements PipeTransform {
  transform(page: number): number | string {
    if (page === -1) {
      return '...';
    } else {
      return page;
    }
  }
}

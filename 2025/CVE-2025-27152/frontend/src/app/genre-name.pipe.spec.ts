import { GenreNamePipe } from './genre-name.pipe';

describe('GenreNamePipe', () => {
  it('create an instance', () => {
    const pipe = new GenreNamePipe();
    expect(pipe).toBeTruthy();
  });
});

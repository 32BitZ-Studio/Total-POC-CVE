import { PagePipe } from './page.pipe';

describe('PagePipe', () => {
  it('create an instance', () => {
    const pipe = new PagePipe();
    expect(pipe).toBeTruthy();
  });

  it('should return the page number when it is not -1', () => {
    const pipe = new PagePipe();
    const result = pipe.transform(2);
    expect(result).toBe(2);
  });

  it('should return ... when it is -1', () => {
    const pipe = new PagePipe();
    const result = pipe.transform(-1);
    expect(result).toBe('...');
  });
});

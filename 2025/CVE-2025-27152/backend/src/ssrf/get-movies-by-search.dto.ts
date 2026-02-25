import { IsOptional, IsString } from 'class-validator';

export class GetMoviesBySearchDto {
  @IsString()
  searchWord: string;

  @IsString()
  @IsOptional()
  pageNumber?: number;
}

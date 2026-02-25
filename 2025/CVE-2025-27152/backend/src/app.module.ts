import { Module, NestModule } from '@nestjs/common';
import { AppController } from './app.controller';
import { ServeStaticModule } from '@nestjs/serve-static';
import { AppService } from './app.service';
import { join } from 'path';
import { MoviesModule } from './movies/movies.module';
import { ToolsModule } from './tools/tools.module';
import { SsrfModule } from './ssrf/ssrf.module';
import { ConfigModule } from '@nestjs/config';
import { MiddlewareConsumer } from '@nestjs/common/interfaces/middleware/middleware-consumer.interface';
import { DownloadsAccessMiddleware } from './downloads/downloads.middleware';

@Module({
  imports: [
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '../..', 'frontend/dist/angular/'),
    }),
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    MoviesModule,
    SsrfModule,
    ToolsModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  public configure(consumer: MiddlewareConsumer): void {
    // make sure that requests to download files are served by the middleware
    consumer.apply(DownloadsAccessMiddleware).forRoutes(`downloads/*param`);
  }
}

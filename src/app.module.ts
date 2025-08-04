import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { DbModule } from './db/db.module';
import { AuthModule } from './auth/auth.module';
import { AdminModule } from './admin/admin.module';
import { OauthModule } from './oauth/oauth.module';

@Module({
  imports: [DbModule, AuthModule, AdminModule, OauthModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}

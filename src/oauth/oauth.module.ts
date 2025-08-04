import { Module } from '@nestjs/common';
import { OauthService } from './oauth.service';
import { OauthController } from './oauth.controller';
import { GoogleStrategy } from './strategies/google.strategy';
import { AuthModule } from 'src/auth/auth.module';
import { PassportModule } from '@nestjs/passport';
import { SessionSerializer } from './serialize/session-serializer';

@Module({
  providers: [OauthService,GoogleStrategy,SessionSerializer],
  controllers: [OauthController],
  imports:[AuthModule,PassportModule.register({session:true})],
})
export class OauthModule {}

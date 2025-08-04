import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { DbModule } from 'src/db/db.module';
import { JwtModule } from '@nestjs/jwt';
import { JWTStrategy } from './strategey/jwt.strategy';
import { PassportModule, PassportStrategy } from '@nestjs/passport';

@Module({
  providers: [AuthService,JWTStrategy],
  controllers: [AuthController],
  imports:[DbModule,
    JwtModule.registerAsync({
      useFactory:async()=>({
        secret:process.env.AUTH_SECRET||'TEST',
        signOptions:{
          expiresIn: '14d'
        }
      })
    }),
    PassportModule
  ],
  exports:[
    JWTStrategy,
    PassportModule,
    AuthService
  ]
})
export class AuthModule {}

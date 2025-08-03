import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { DbModule } from 'src/db/db.module';
import { JwtModule } from '@nestjs/jwt';

@Module({
  providers: [AuthService],
  controllers: [AuthController],
  imports:[DbModule,
    JwtModule.registerAsync({
      useFactory:async()=>({
        secret:process.env.AUTH_SECRET||'TEST',
        signOptions:{
          expiresIn: '14d'
        }
      })
    })
  ]
})
export class AuthModule {}

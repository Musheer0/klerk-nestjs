import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as session from 'express-session'
import * as passport from 'passport'
async function bootstrap() {

  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({
    whitelist:true,
    forbidNonWhitelisted:process.env.NODE_ENV==='production'
  }));
  app.use(session({
    secret:process.env.AUTH_SECRET!,
    saveUninitialized:false,
    resave:false,
    cookie:{maxAge:  8*24*60*60000 }
    
    
  }));
  app.use(passport.initialize());
  app.use(passport.session())
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();

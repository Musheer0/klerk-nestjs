import { Controller, Post, Req } from '@nestjs/common';
import { SignUpDto } from './dto/signup.dto';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/signin.dto';

@Controller('auth')
export class AuthController {
    constructor (private readonly auth_service:AuthService){}
    @Post('/sign-up')
    signUpUser(@Req() req:SignUpDto){
        return this.auth_service.CreateUser(req)
    }
    @Post('/sign-un')
    signInUser(@Req() req:SignInDto){
      return this.auth_service.SignInUser(req,)
    }
}

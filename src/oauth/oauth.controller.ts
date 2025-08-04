import { Controller, Get, UseGuards } from '@nestjs/common';
import { GoogleAuthGuard } from './guards/google.guard';

@Controller('oauth')
export class OauthController {

    @Get('/google/login')
    @UseGuards(GoogleAuthGuard)
    handleLogin(){
        return {msg:'google auth'}
    }

    @Get('/callback/google')
    @UseGuards(GoogleAuthGuard)
    handleRedirect(){
        return {
            mesg:true
        }
    }
}

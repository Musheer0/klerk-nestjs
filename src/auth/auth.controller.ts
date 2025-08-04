import { Body, Controller, Delete, Get, Param, Patch, Post, Query, Req, Request, UseGuards } from '@nestjs/common';
import { SignUpDto } from './dto/signup.dto';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/signin.dto';
import { GetIp } from 'src/decorators/ip.decorator';
import { UserAgent } from 'src/decorators/user-agent.decorator';
import { VerifyTokenDto } from './dto/verifiytoken.dto';
import { RequestTokenDto } from './dto/request-token.dto';
import { ResetPasswordDto } from './dto/resetpassword.dto';
import { GetJWtToken } from 'src/decorators/jwt.decorator';
import { JWTGuard } from './guards/jwt.guard';
import { PublicAuthRoute } from './guards/public.route.guard';
import { EditBasicUserInfoDto } from './dto/updatebasicUserInfo';
import { SessionGuard } from './guards/session.guard';

@Controller('auth')
export class AuthController {
    constructor (private readonly auth_service:AuthService){}
    @UseGuards(PublicAuthRoute)
    @Post('/sign-up')
    signUpUser(@Body() req:SignUpDto){
        return this.auth_service.CreateUser(req)
    }
    @Post('/sign-in')
    signInUser(@Body() req:SignInDto,@GetIp()ip:string|null,@UserAgent() userAgent:string){
      return this.auth_service.SignInUser(req,ip||'0.0.0',userAgent)
    }
    @Post('/verify/:id')
    verifyToken(@Body() body:VerifyTokenDto,@Param() param:{id:string},@GetIp()ip:string|null,@UserAgent() userAgent:string){
        return this.auth_service.verify_token(body,param.id,ip||'0.0.0',userAgent)
    }
    @UseGuards(JWTGuard)
    @Get('/verify/token')
    verifysessionToken(@GetJWtToken() token:string,@UserAgent() userAgent:string){

        return this.auth_service.verify_and_refresh_session(token,userAgent)
    }
    @Post('/request/password-reset')
    requestResetPasswordToken(@Body() body:RequestTokenDto){
        return this.auth_service.request_password_reset(body)
    }
    @Patch('/reset/password/:id')
    resetPassword( @Body() body:ResetPasswordDto,@Param() param:{id:string}){
        return this.auth_service.reset_password(body,param.id)
    }
    @UseGuards(JWTGuard)
    @Delete('/logout')
    logout(@GetJWtToken() token:string){
        return this.auth_service.logout(token)
    }
    @UseGuards(JWTGuard,SessionGuard)
    @Patch('/user/edit/basic')
    editBasicInfo(@Body() body:EditBasicUserInfoDto,@Request() req){
        return this.auth_service.updateBasicInfo(body,req.user.user_id)
    }
    @UseGuards(JWTGuard,SessionGuard)
    @Patch('/user/mfa/enable')
    EnableMFA(@Request() req,@Query("type") type:"email"|"phone"){
        return this.auth_service.enablemfa(req.user.user_id,type)
    }
    @UseGuards(JWTGuard,SessionGuard)
    @Patch('/user/mfa/disable')
    DisableMFA(@Request() req,){
        return this.auth_service.disablemfa(req.user.user_id)
    }


}

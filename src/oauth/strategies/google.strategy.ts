import { Inject, Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Profile, Strategy } from "passport-google-oauth20";
import { AuthService } from "src/auth/auth.service";
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy){
    constructor(
         private readonly auth_serive:AuthService
    ){
        super({
            clientID:process.env.GOOGLE_CLIENT_ID!,
            clientSecret:process.env.GOOGLE_CLIENT_SECRET!,
            callbackURL: 'http://localhost:3500/oauth/callback/google',
            scope:['profile','email'],
            passReqToCallback:true,
        });
    }

    async validate(req:Request,accessTOken:string,refreshToken:string,profile:Profile) {
       
        return this.auth_serive.OAuthGoogleLogin(profile,req.headers['X-forwarder-for']||'0.0.0.',req.headers['user-agent']||'node')
    }
}
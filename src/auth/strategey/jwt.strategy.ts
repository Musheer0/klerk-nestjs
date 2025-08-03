import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { Tjwt_session } from "../auth.service";
@Injectable()
export class JWTStrategy extends PassportStrategy(Strategy) {
    constructor(){
        super({
             jwtFromRequest:ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration:false,
            secretOrKey:process.env.AUTH_SECRET||'SECRET'
        })
    }
    async validate(payload){
        return payload
    }
}
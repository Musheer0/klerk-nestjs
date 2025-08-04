import { Inject } from "@nestjs/common";
import { PassportSerializer } from "@nestjs/passport";
import { OauthService } from "../oauth.service";

export class SessionSerializer extends PassportSerializer{
    constructor(
    ){
        super()
    }
    serializeUser(user: any, done: Function) {
        done(null,user);
    }
    deserializeUser(payload: any, done: Function) {
        return done(null,payload)
    }
}
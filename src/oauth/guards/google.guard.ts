import { ExecutionContext, Injectable } from "@nestjs/common"
import { AuthGuard } from "@nestjs/passport"
@Injectable()
export class GoogleAuthGuard extends AuthGuard('google'){
    async canActivate(context: ExecutionContext) {
            const activate =await  super.canActivate(context) as boolean;
            const req = context.switchToHttp().getRequest();
            const res =context.switchToHttp().getResponse();
            await super.logIn(req);
            res.cookie('session',req?.user,{
                expires:  new Date(Date.now() + 14 * 24 * 60 * 60 * 1000),
                 httpOnly: true,         
                 secure: true,            
                sameSite: 'lax',         
                path: '/',  
            });
            return res.redirect(process.env.FRONT_END!)
    }

}
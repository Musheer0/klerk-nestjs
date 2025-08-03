import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
import { DbService } from "src/db/db.service";

@Injectable()
export class SessionGuard implements CanActivate{
    constructor(private db:DbService){}
   async canActivate(context: ExecutionContext){
    console.log('hello....................')
        const req = context.switchToHttp().getRequest();
        console.log(req.user)
        if(!req.user) return false;
        const session = await  this.db.session.findFirst({
            where:{
                id:req.user.session,
                user_id: req.user.user_id,
                expires_at: {gt: new Date()}
            }
        });
        if(!session || session.scope==='BASIC_INFO')return false;
        req.session = session;
        return true

    }
}
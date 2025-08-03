import { createParamDecorator } from "@nestjs/common";

export const GetJWtToken  =createParamDecorator(
    (handler,ctx)=>{
            const req = ctx.switchToHttp().getRequest<Request>();
            const token = req.headers['authorization']?.split('Bearer ')[1]
            return token|| null
    }
)
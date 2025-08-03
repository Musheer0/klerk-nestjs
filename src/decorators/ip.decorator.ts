import { createParamDecorator, ExecutionContext } from "@nestjs/common";

export const GetIp = createParamDecorator(
    (data:unknown,ctx:ExecutionContext)=>{
            const req = ctx.switchToHttp().getRequest();

    const forwarded = req.headers['x-forwarded-for'];
    const ip =
      typeof forwarded === 'string'
        ? forwarded.split(',')[0].trim()
        : req.socket?.remoteAddress;
        return ip || null;

    }
)
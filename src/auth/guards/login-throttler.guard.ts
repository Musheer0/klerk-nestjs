import { ThrottlerException, ThrottlerGuard } from "@nestjs/throttler";

export class LoginThrottlerGuard extends ThrottlerGuard{
    protected async getTracker(req: Record<string, any>): Promise<string> {
        const key = req?.body?.email||req?.body?.phone_number;
        return `login-${key}`
    }
      protected getLimit(){
        return Promise.resolve(4)
    }
    protected getTtl(){
        return Promise.resolve(60000)
    }
    protected async throwThrottlingException(): Promise<void> {
        throw new ThrottlerException("too many login attempts try again after 1 min")
    }
}
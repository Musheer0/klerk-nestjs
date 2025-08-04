import { hash, verify } from 'argon2';
import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  NotFoundException
} from '@nestjs/common';
import { DbService } from 'src/db/db.service';
import { SignUpDto } from './dto/signup.dto';
import { SignInDto } from './dto/signin.dto';
import { VerifyTokenDto } from './dto/verifiytoken.dto';
import { ResetPasswordDto } from './dto/resetpassword.dto';
import { JwtService } from '@nestjs/jwt';
import otpGenerator from 'otp-generator';
import { scope, verification_token_scope } from '@prisma/client';
import { RequestTokenDto } from './dto/request-token.dto';
import { EditBasicUserInfoDto } from './dto/updatebasicUserInfo';
import { sendWhatsAppCode } from 'src/lib/send-whatsapp-code';
import { sendEmail } from 'src/lib/send-email';
import { otpEmailTemplate } from './email/otp-email-template';

export type Tjwt_session = {
  session: string;
  session_expires_at: Date;
  user_id: string;
  image_url: string;
};

@Injectable()
export class AuthService {
  constructor(
    private db: DbService,
    private jwtService: JwtService
  ) {}

  private async createSessionAndToken(
    userId: string,
    ip: string,
    user_agent: string,
    image_url: string
  ) {
    const expires_at = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000); // 14 days
    const session = await this.db.session.create({
      data: {
        user_id: userId,
        ip,
        user_agent,
        expires_at,
        scope: scope.FULL
      }
    });

    const jwt_token = await this.jwtService.sign({
      session: session.id,
      session_expires_at: session.expires_at,
      user_id: session.user_id,
    });

    return { session, jwt_token };
  }

  private isSessionExpiringSoon(expires_at: Date): boolean {
    const diff = expires_at.getTime() - Date.now();
    return diff < (24 * 60 * 60 * 1000);
  }

  /**
   * 🔁 Reusable token creator for all scopes
   */
  private async createVerificationToken(userId: string, scope: verification_token_scope,reciver:string,type?:"email"|"phone") {
    const otp = 'lookslim44'

    const verification = await this.db.verification_token.create({
      data: {
        identifier: userId,
        token: otp,
        scope,
        expires_at: new Date(Date.now() + 15 * 60 * 1000)
      }
    });

    if (process.env.NODE_ENV !== 'production') {
      console.warn(`${scope.toUpperCase()} OTP (dev only):`, verification.token);
    }
    if(scope==='verify_phone_number' || type==='phone'){
      await sendWhatsAppCode(otp, reciver)
    }
    else{
      await sendEmail(reciver,otpEmailTemplate({otp}),'Verify your email')
    }

    return {
      verification_id: verification.id,
      scope: verification.scope
    };
  }

  async CreateUser(data: SignUpDto) {
    const { username, password, phone_number, email } = data;
    if (!email && !phone_number || email && phone_number) {
      throw new BadRequestException("Either email or phone number is required");
    }

    const existingUser = await this.db.user.findFirst({
      where: {
        OR: [
          { primary_email: email },
          { primary_phone_number: phone_number },
          { username }
        ]
      }
    });

    if (existingUser?.username === username) {
      throw new ConflictException("Username already exists");
    } else if (existingUser) {
      throw new ConflictException("User already exists");
    }

    const hashedPassword = await hash(password, {
      secret: Buffer.from(process.env.AUTH_SECRET || 'TEST')
    });

    const new_user = await this.db.user.create({
      data: {
        password: hashedPassword,
        primary_email: email || null,
        primary_phone_number: phone_number || null,
        name: data.name || null,
        username
      }
    });

    const token = await this.createVerificationToken(new_user.id, email ? verification_token_scope.verify_email:verification_token_scope.verify_phone_number,
      new_user.primary_email||new_user.primary_phone_number!
    );

    return {
      success: true,
      message: `OTP sent to your ${email ? 'email' : 'phone number'}`,
      ...token
    };
  }

  async SignInUser(data: SignInDto, ip: string, user_agent: string) {
    const { email, password, phone_number, username } = data;

    if (!password) throw new BadRequestException("Invalid request");

    const user = await this.db.user.findFirst({
      where: {
        OR: [
          { username },
          { primary_email: email },
          { primary_phone_number: phone_number }
        ]
      }
    });

    if (!user || !user.password) throw new BadRequestException("Invalid credentials");

    const isCorrectPassword = await verify(user.password, password, {
      secret: Buffer.from(process.env.AUTH_SECRET || 'TEST')
    });

    if (!isCorrectPassword) throw new BadRequestException("Invalid credentials");

    const isUserVerified = user.primary_email ? user.is_email_verified : user.is_phone_number_verified;
    if (!isUserVerified) {
await this.db.verification_token.deleteMany({
  where: {
    identifier: user.id,
    scope: user.primary_email ? verification_token_scope.verify_email : verification_token_scope.verify_phone_number
  }
});

      const token = await this.createVerificationToken(
        user.id,
        user.primary_email ? verification_token_scope.verify_email : verification_token_scope.verify_phone_number,
        user.primary_email||user.primary_phone_number!
      );
      return {
        success: true,
        message: `You're not verified. Check your ${user.primary_email ? 'email' : 'phone number'}`,
        ...token
      };
    }

    if (user.mfa_enabled) {
        await this.db.verification_token.deleteMany({
    where: {
      identifier: user.id,
      scope: verification_token_scope.mfa
    }
  });
      const token = await this.createVerificationToken(user.id, verification_token_scope.mfa,
        user.primary_email||user.primary_phone_number!
      );
      return {
        success: true,
        message: 'MFA OTP sent',
        ...token
      };
    }

    const { jwt_token } = await this.createSessionAndToken(user.id, ip, user_agent, user.image_url);

    return {
      success: true,
      message: 'Login successful',
      token: jwt_token
    };
  }

  async verify_token(data: VerifyTokenDto, id: string, ip: string, user_agent: string) {
    const token = await this.db.verification_token.findFirst({
      where: { token: data.token, id }
    });

    if (!token) throw new NotFoundException("Invalid token");
    if (new Date(token.expires_at) < new Date()) throw new BadRequestException("Token expired");

    const user = await this.db.user.findUnique({ where: { id: token.identifier } });
    if (!user) throw new NotFoundException("User not found");

    await this.db.verification_token.delete({ where: { id: token.id } });

    switch (token.scope) {
      case 'verify_email':
        await this.db.user.update({
          where: { id: user.id },
          data: {
            is_email_verified: true,
            email_verified_at: new Date()
          }
        });
        return { success: true, message: 'Email verified' };

      case 'verify_phone_number':
        await this.db.user.update({
          where: { id: user.id },
          data: {
            is_phone_number_verified: true,
            phone_number_verified_at: new Date()
          }
        });
        return { success: true, message: 'Phone number verified' };

      case 'mfa': {
        const { jwt_token } = await this.createSessionAndToken(
          token.identifier,
          ip,
          user_agent,
          user.image_url
        );
        return { success: true, message: 'Login successful', token: jwt_token };
      }
      case 'enable_mfa':{
          try {
            const updated_user =await this.db.user.update({
              where:{
                id:user.id
              },
              data:{
                mfa_enabled:true,
                mfa_enabled_at: new Date(),
                mfa_type:  user.primary_email ? 'email':'phone'
              }
            });
            return {
              success:true,
              mfa_type: updated_user.mfa_type,
              mfa_enabled:updated_user.mfa_enabled
            }
          } catch (error) {
            throw new InternalServerErrorException("error enabling mfa try again")
          }
      }

      default:
        throw new BadRequestException(`Unknown token scope: ${token.scope}`);
    }
  }

  async reset_password(data: ResetPasswordDto, id: string) {
    const { new_password, token } = data;

    const verification_token = await this.db.verification_token.findFirst({
      where: { token, id, scope: verification_token_scope.reset_password }
    });

    if (!verification_token) throw new NotFoundException("Invalid token");
    if (new Date(verification_token.expires_at) < new Date()) throw new BadRequestException("Token expired");

    const hashed_password = await hash(new_password, {
      secret: Buffer.from(process.env.AUTH_SECRET || 'TEST')
    });

    const user = await this.db.user.update({
      where: { id: verification_token.identifier },
      data: { password: hashed_password }
    });
    await this.db.verification_token.delete({where:{id:verification_token.id}})
    await this.db.session.deleteMany({ where: { user_id: user.id } });
    return {
        success:true,
        message: 'password reset successfull you have been logged out of your all devices'
    }
  }

  async request_password_reset(data:RequestTokenDto) {
    const {username,email,phone_number} = data
    const user = await this.db.user.findFirst({
      where: {
        OR: [
          { primary_email: email },
          { primary_phone_number: phone_number },
          {username}
        ]
      }
    });
    if (!user) throw new NotFoundException("User not found");
await this.db.verification_token.deleteMany({
  where: {
    identifier: user.id,
    scope: verification_token_scope.reset_password
  }
});

    const token = await this.createVerificationToken(
      user.id,
      verification_token_scope.reset_password,
      user.primary_email||user.primary_phone_number!
    );

    return {
      success: true,
      message: `To reset your password, check your ${user.primary_email ? 'email' : 'phone number'}`,
      ...token
    };
  }

  async verify_and_refresh_session(token: string, user_agent: string) {
    const jwt_session: Tjwt_session = await this.jwtService.decode(token) as any;
        if (!jwt_session) throw new NotFoundException("Invalid session");

    const session = await this.db.session.findFirst({
      where: {
        id: jwt_session.session,
        user_id: jwt_session.user_id,
        user_agent
      }
    });

    if (!session) throw new NotFoundException("Invalid session");

    if (new Date(session.expires_at) <= new Date()) {
      await this.db.session.delete({ where: { id: session.id } });
      throw new NotFoundException("Session expired");
    }

    const user = await this.db.user.findUnique({
      where: { id: session.user_id }
    });

    if (!user) {
      await this.db.session.deleteMany({ where: { user_id: session.user_id } });
      throw new NotFoundException("User not found");
    }

    let currentSession = session;
    if (this.isSessionExpiringSoon(session.expires_at)) {
      currentSession = await this.db.session.update({
        where: { id: session.id },
        data: {
          expires_at: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000)
        }
      });
    }

    return {
      session_id: currentSession.id,
      user: {
        id: user.id,
        email: user.primary_email,
        phone_number: user.primary_phone_number,
        name: user.name,
        username: user.username,
        email_verified: user.is_email_verified,
        phone_number_verified: user.is_phone_number_verified,
        mfa: user.mfa_enabled,
        image_url: user.image_url
      }
    };
  }
  async logout(token: string) {
  const jwt_session: Tjwt_session = await this.jwtService.decode(token) as any;

  if (!jwt_session?.session || !jwt_session?.user_id) {
    throw new BadRequestException("Invalid or malformed token");
  }

  const session = await this.db.session.findFirst({
    where: {
      id: jwt_session.session,
      user_id: jwt_session.user_id,
    }
  });

  if (!session) {
    throw new NotFoundException("Session not found or already expired");
  }

  await this.db.session.delete({
    where: { id: session.id }
  });

  return {
    success: true,
    message: "Logged out successfully"
  };
}
async updateBasicInfo(data:EditBasicUserInfoDto,userId:string){
    const keys = Object.keys(data)
    try {
     const user =  await this.db.user.update({
        where:{
          id:userId
        },
        data:data
      });
      console.log()
      return {
        success:true,
        message: 'user updated success fully',
        updated_fields: keys.reduce((acc, k) => {
  acc[k] = user[k];
  return acc;
}, {})

      }
    } catch (error) {
      console.error(error)
      throw new InternalServerErrorException("internal server error")
    }
}
 async enablemfa  (userId:string,type:"email"|"phone"){
  try {
      const user = await this.db.user.findFirst({
        where:{
          id: userId
        }
      });
      if(!user) throw new NotFoundException("invalid session");
      if(type==='email'&& !user.is_email_verified || type==='phone' && !user.is_phone_number_verified) throw new BadRequestException(`please verifiy your ${type}`);
       const token = await this.createVerificationToken(
        user.id,
        'enable_mfa',
        type==='email'? user.primary_email! : user.primary_phone_number!,
        type
       );
       return{
        success:true,
        ...token
       }
  } catch (error) {
    console.error(error);
    throw new InternalServerErrorException("error enabling mfa")
  }
 }
 async disablemfa (userId:string){
  try {
      const user = await this.db.user.findFirst({
        where:{
          id: userId
        }
      });
      if(!user) throw new NotFoundException("invalid session");
      await this.db.user.update({
        where:{
          id:user.id
        },
        data:{
          mfa_enabled:false,
          mfa_enabled_at:null
        }
      });
      return{
        success:true,
        message:'mfa disabled'
      }
  } catch (error) {
    console.error(error);
    throw new InternalServerErrorException("error enabling mfa")
  }
 }
 
}

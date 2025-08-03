/**
 * AuthService handles user authentication flows including sign up,
 * login, MFA, OTP verification, password reset, and session management.
 */

import { hash, verify } from 'argon2';
import {
  BadRequestException,
  ConflictException,
  Injectable,
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

/**
 * JWT payload structure used across the app.
 */
type Tjwt_session = {
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

  /**
   * Helper: Creates a session in the DB and returns a signed JWT.
   * @param userId - User ID to bind the session to.
   * @param ip - IP address from which the session is initiated.
   * @param user_agent - User-Agent string for session tracking.
   * @param image_url - Image URL to include in JWT payload.
   * @returns Session record and JWT string.
   */
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

    const jwt_token = await this.jwtService.sign(JSON.stringify({
      session: session.id,
      session_expires_at: session.expires_at,
      user_id: session.user_id,
      image_url
    }));

    return { session, jwt_token };
  }

  /**
   * Helper: Checks whether the session is expiring within 24 hours.
   * @param expires_at - Expiry date of the session.
   * @returns True if session expires in < 1 day, else false.
   */
  private isSessionExpiringSoon(expires_at: Date): boolean {
    const diff = expires_at.getTime() - Date.now();
    return diff < (24 * 60 * 60 * 1000); // less than 1 day
  }

  /**
   * Registers a new user and sends an OTP to verify their email or phone.
   * @param data - User sign-up DTO.
   * @throws ConflictException if the user/email/phone already exists.
   * @returns A success message about OTP delivery.
   */
  async CreateUser(data: SignUpDto) {
    const { username, passoword, phone_number, email } = data;

    if (!email && !phone_number) {
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

    const hashedPassword = await hash(passoword, {
      secret: Buffer.from(process.env.AUTH_SECRET || 'TEST')
    });

    const new_user = await this.db.user.create({
      data: {
        ...data,
        password: hashedPassword
      }
    });

    const verification_token = await this.db.verification_token.create({
      data: {
        identifier: new_user.id,
        token: otpGenerator.generate(6),
        expires_at: new Date(Date.now() + 15 * 60 * 1000),
        scope: verification_token_scope.verify_email
      }
    });

    if (process.env.NODE_ENV !== 'production') {
      console.warn('OTP (dev only):', verification_token.token);
    }

    return {
      success: true,
      message: `OTP sent to your ${email ? 'email' : 'phone number'}`
    };
  }

  /**
   * Authenticates the user and returns a JWT.
   * If MFA is enabled, an OTP is sent instead.
   * @param data - Login DTO with email/phone/username/password.
   * @param ip - Client IP address.
   * @param user_agent - Client User-Agent string.
   * @throws BadRequestException on invalid login or password.
   * @returns JWT token or OTP-sent message.
   */
  async SignInUser(data: SignInDto, ip: string, user_agent: string) {
    const { email, passoword, phone_number, username } = data;

    if (!email || !phone_number || !username || !passoword) {
      throw new BadRequestException("Invalid request");
    }

    const user = await this.db.user.findFirst({
      where: {
        OR: [
          { username },
          { primary_email: email },
          { primary_phone_number: phone_number }
        ]
      }
    });

    if (!user || !user.password) {
      throw new BadRequestException("Invalid credentials");
    }

    const isCorrectPassword = await verify(user.password, passoword, {
      secret: Buffer.from(process.env.AUTH_SECRET || 'TEST')
    });

    if (!isCorrectPassword) {
      throw new BadRequestException("Invalid credentials");
    }

    if (user.mfa_enabled) {
      const verification_token = await this.db.verification_token.create({
        data: {
          identifier: user.id,
          scope: verification_token_scope.mfa,
          expires_at: new Date(Date.now() + 15 * 60 * 1000),
          token: otpGenerator.generate(6)
        }
      });

      console.warn('MFA OTP (dev only):', verification_token.token);

      return {
        success: true,
        message: `OTP sent to your ${user.primary_email ? 'email' : 'phone number'}`
      };
    }

    const { jwt_token } = await this.createSessionAndToken(user.id, ip, user_agent, user.image_url);

    return {
      success: true,
      message: 'Login successful',
      token: jwt_token
    };
  }

  /**
   * Verifies the provided OTP and performs the appropriate action
   * based on the verification scope: email, phone, or MFA.
   * @param data - DTO containing OTP token string.
   * @param id - Token ID from frontend context.
   * @param ip - IP address.
   * @param user_agent - User-Agent.
   * @throws BadRequestException or NotFoundException on failure.
   */
  async verify_token(data: VerifyTokenDto, id: string, ip: string, user_agent: string) {
    const token = await this.db.verification_token.findFirst({
      where: { token: data.token, id }
    });

    if (!token) throw new NotFoundException("Invalid token");
    if (new Date(token.expires_at) < new Date()) throw new BadRequestException("Token expired");

    const user = await this.db.user.findUnique({ where: { id: token.identifier } });
    if (!user) throw new NotFoundException("User not found");
    await this.db.verification_token.delete({
        where:{
            id:token.id
        }
    });
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

      default:
        throw new BadRequestException(`Unknown token scope: ${token.scope}`);
    }
  }

  /**
   * Resets user password using a valid token.
   * All user sessions are cleared after password reset.
   * @param data - New password + token string.
   * @param id - Verification token ID.
   * @throws NotFoundException if token/user is invalid.
   */
  async reset_password(data: ResetPasswordDto, id: string) {
    const { new_password, token } = data;

    const verification_token = await this.db.verification_token.findFirst({
      where: { token, id }
    });

    if (!verification_token) throw new NotFoundException("Invalid token");
    if (new Date(verification_token.expires_at) < new Date()) throw new BadRequestException("Token expired");

    try {
      const hashed_password = await hash(new_password, {
        secret: Buffer.from(process.env.AUTH_SECRET || 'TEST')
      });

      const user = await this.db.user.update({
        where: { id: verification_token.identifier },
        data: { password: hashed_password }
      });

      await this.db.session.deleteMany({ where: { user_id: user.id } });

    } catch (error) {
      console.error(error);
      throw new NotFoundException("User not found");
    }
  }

  /**
   * Validates an existing session JWT.
   * If session is about to expire (< 1 day), it refreshes the expiry.
   * @param token - JWT session token.
   * @param user_agent - User-Agent of the request to validate session binding.
   * @returns User session details.
   * @throws NotFoundException if session is invalid/expired.
   */
  async verify_and_refresh_session(token: string, user_agent: string) {
    const jwt_session: Tjwt_session = await this.jwtService.decode(token) as any;

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

    // 🔄 Refresh session if it's about to expire
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
}

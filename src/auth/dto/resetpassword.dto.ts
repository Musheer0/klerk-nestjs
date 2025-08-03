import {IsString, Matches, MinLength} from 'class-validator'
import { VerifyTokenDto } from './verifiytoken.dto'
export class ResetPasswordDto extends VerifyTokenDto {
    @IsString()
    @MinLength(8) // at least 8 chars
  @Matches(/[A-Z]/, { message: 'Password must contain at least one uppercase letter' })
  @Matches(/[a-z]/, { message: 'Password must contain at least one lowercase letter' })
  @Matches(/[0-9]/, { message: 'Password must contain at least one digit' })
    new_password:string

}
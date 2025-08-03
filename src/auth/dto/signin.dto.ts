import {IsString,IsEmail, IsOptional, IsPhoneNumber, MinLength, Matches} from 'class-validator'
export class SignInDto{
    
    @IsOptional()
    @IsString()
    username:string


    @IsOptional()
    @IsEmail()
    email:string

    @IsOptional()
    @IsPhoneNumber()
    phone_number:string

    @IsString()
     @MinLength(8) // at least 8 chars
      @Matches(/[A-Z]/, { message: 'Password must contain at least one uppercase letter' })
      @Matches(/[a-z]/, { message: 'Password must contain at least one lowercase letter' })
      @Matches(/[0-9]/, { message: 'Password must contain at least one digit' })
    passoword:string

}
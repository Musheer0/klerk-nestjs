import {IsString,IsEmail, IsOptional, IsPhoneNumber,  IsUrl, MinLength, Matches} from 'class-validator'
export class SignUpDto{
    
    @IsString()
    username:string


    @IsOptional()
    @IsString()
    name:string

    @IsOptional()
    @IsEmail()
    email:string

    @IsOptional()
    @IsPhoneNumber()
    phone_number:string

    @IsOptional()
    @IsUrl()
    image_url:string

    @MinLength(8) // at least 8 chars
    @Matches(/[A-Z]/, { message: 'Password must contain at least one uppercase letter' })
    @Matches(/[a-z]/, { message: 'Password must contain at least one lowercase letter' })
    @Matches(/[0-9]/, { message: 'Password must contain at least one digit' })
    passoword:string
}
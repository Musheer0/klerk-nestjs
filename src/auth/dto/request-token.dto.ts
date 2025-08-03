import {IsString,IsEmail, IsOptional, IsPhoneNumber} from 'class-validator'
export class RequestTokenDto{
    
    @IsOptional()
    @IsString()
    username:string


    @IsOptional()
    @IsEmail()
    email:string

    @IsOptional()
    @IsPhoneNumber()
    phone_number:string
}
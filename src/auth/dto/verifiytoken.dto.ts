import {IsString,IsEmail, IsOptional, IsPhoneNumber,  IsUrl, IsNumber} from 'class-validator'
export class VerifyTokenDto{
    @IsString()
    token:string
}
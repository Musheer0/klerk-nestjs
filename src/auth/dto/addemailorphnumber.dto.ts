import {IsEmail, IsOptional, IsPhoneNumber} from 'class-validator'
import { VerifyTokenDto } from './verifiytoken.dto'

export class AddEmailOrPhoneNumberDto extends VerifyTokenDto{
    @IsOptional()
    @IsEmail()
    new_email:string

    @IsOptional()
    @IsPhoneNumber()
    new_phone_number:string

}
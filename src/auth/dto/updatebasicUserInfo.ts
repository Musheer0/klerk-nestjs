import { IsOptional, IsString, IsUrl, MinLength } from "class-validator";

export class EditBasicUserInfoDto{

    @IsOptional()
    @IsString()
    @MinLength(4)
    username:string

    @IsOptional()
    @IsUrl()
    image_url:string

    @IsOptional()
    @IsString()
    @MinLength(2)
    name:string
}
import { IsString, IsUrl } from "class-validator";

export class ChangeProfileDto{
    @IsString()
    @IsUrl()
    image_url:string
}
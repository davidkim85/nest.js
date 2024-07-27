import { IsEmail,IsString } from 'class-validator';
export class AuthDto {
	_id:string;
	@IsString()
	username: string;
	@IsString()
	password: string;
  }
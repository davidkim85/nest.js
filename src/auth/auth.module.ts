import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserModel } from "../auth/auth.model";
import { TypegooseModule } from '@m8a/nestjs-typegoose';
import { JwtModule } from '@nestjs/jwt';
import { AccessTokenStrategy} from './strategies/accessToken.strategy';
import { RefreshTokenStrategy } from './strategies/refreshToken.strategy';



@Module({
	controllers: [AuthController],
	imports: [
		TypegooseModule.forFeature([{typegooseClass: UserModel,schemaOptions: {collection: 'User'}}]),
		JwtModule.register({}),
	],
	providers: [AuthService,AccessTokenStrategy, RefreshTokenStrategy]
})
export class AuthModule { }






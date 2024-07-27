import { Injectable } from '@nestjs/common';
import { pre,post, prop } from '@typegoose/typegoose';
import { TimeStamps, Base } from '@typegoose/typegoose/lib/defaultClasses';
import { genSaltSync, hashSync} from 'bcryptjs';


export interface UserModel extends Base { }
@pre<UserModel>('save',function (next) {
	if (!this.isModified("password")) {
	  next();
	}
	const salt = genSaltSync(10);
	this.password = hashSync(this.password, salt);
	next();
  })


@Injectable()
export class UserModel extends TimeStamps {	
  @prop()
  username: string;
  @prop({ unique: true })
  email: string;
  @prop()
  password: string;
  @prop()
  refreshToken:string;
  
}







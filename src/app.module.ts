import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypegooseModule } from '@m8a/nestjs-typegoose';



@Module({
  imports: [
    ConfigModule.forRoot(),
    TypegooseModule.forRoot('mongodb+srv://poramok:S8ho1ExcOkmn07SS@cluster1.kcqimki.mongodb.net/?retryWrites=true&w=majority&appName=Cluster1'),
    AuthModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}

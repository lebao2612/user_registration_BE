import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { User, UserSchema } from './user.schema';

const UserMongooseModule = MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]);

@Module({
  imports: [UserMongooseModule],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService, UserMongooseModule] // Export để module khác dùng
})
export class UserModule {}
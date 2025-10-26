import { Controller, Post, Body } from '@nestjs/common';
import { UserService } from './user.service';
import { RegisterDto } from './dto/register.dto';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    const { email, password } = registerDto;
    const user = await this.userService.register(email, password);
    return { 
      message: 'User registered successfully',
      user: {
        email: user.email,
        createdAt: user.createdAt
      }
    };
  }
}
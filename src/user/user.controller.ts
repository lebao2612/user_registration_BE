import { Controller, Post, Body, UseGuards, Get, Request } from '@nestjs/common';
import { UserService } from './user.service';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';

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

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@Request() req) {
    // req.user được trả về từ JwtStrategy
    const userId = req.user.userId;
    const user = await this.userService.findById(userId);

    if (!user) {
      throw new Error('User not found');
    }

    return {
      email: user.email,
      createdAt: user.createdAt
    };
  }
}
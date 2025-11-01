import { Controller, Post, Body, UseGuards, Request, HttpCode, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';

@Controller('auth')
export class AuthController {
 constructor(private authService: AuthService) {}

    @Post('login')
    @HttpCode(HttpStatus.OK)
    async login(@Body() loginDto: LoginDto) {
        // Yêu cầu 
        return this.authService.login(loginDto);
    }

    @UseGuards(JwtAuthGuard) // Phải đăng nhập mới được logout
    @Post('logout')
    @HttpCode(HttpStatus.OK)
    async logout(@Request() req) {
        // Yêu cầu [cite: 16, 22]
        const userId = req.user.userId;
        return this.authService.logout(userId);
    }

    @UseGuards(JwtRefreshGuard) // Dùng Guard riêng để validate Refresh Token
    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    async refreshTokens(@Request() req) {
        // Yêu cầu 
        const userId = req.user.userId;
        const refreshToken = req.user.refreshToken;
    return this.authService.refreshTokens(userId, refreshToken);
    }
}
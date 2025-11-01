import { Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { UserDocument } from 'src/user/user.schema';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  /**
   * Tạo Access Token và Refresh Token
   */
  private async getTokens(userId: string, email: string) {
    const payload = { sub: userId, email };

    const [accessToken, refreshToken] = await Promise.all([
      // Access Token
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('JWT_SECRET'),
        expiresIn: this.configService.get('JWT_EXPIRATION'),
      }),
      // Refresh Token
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get('JWT_REFRESH_EXPIRATION'),
      }),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  /**
   * Xác thực người dùng (check email, password)
   */
  async validateUser(loginDto: LoginDto): Promise<UserDocument> {
    const { email, password } = loginDto;
    const user = await this.userService.findByEmail(email);

    if (user && (await bcrypt.compare(password, user.password))) {
        return user;
    }
    throw new UnauthorizedException('Invalid credentials');
  }

  /**
   * Xử lý đăng nhập
   */
    async login(loginDto: LoginDto) {
    // 1. Validate user
        const user = await this.validateUser(loginDto);

        // 2. Tạo tokens
        const tokens = await this.getTokens(String(user._id), user.email);

        // 3. Lưu refresh token vào DB
        await this.userService.setRefreshToken(String(user._id), tokens.refreshToken);

        // 4. Trả về tokens cho client
        return tokens;
    }

  /**
   * Xử lý đăng xuất
   */
    async logout(userId: string) {
        // Xóa refresh token khỏi DB
        await this.userService.removeRefreshToken(userId);
        return { message: 'Logged out successfully' };
    }

  /**
   * Xử lý làm mới token
   */
  async refreshTokens(userId: string, rt: string) {
    // 1. Tìm user
    const user = await this.userService.findById(userId);
    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Access Denied');
    }

    // 2. Kiểm tra refresh token (rt) gửi lên có khớp với rt trong DB không
    const rtMatches = await bcrypt.compare(rt, user.refreshToken);
    if (!rtMatches) {
      throw new ForbiddenException('Access Denied');
    }

    // 3. Tạo tokens mới
    const tokens = await this.getTokens(String(user._id), user.email);
    
    // 4. Cập nhật refresh token mới vào DB
    await this.userService.setRefreshToken(String(user._id), tokens.refreshToken);

    return tokens;
  }
}
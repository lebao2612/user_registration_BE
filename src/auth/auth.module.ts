import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UserModule } from 'src/user/user.module'; // Import UserModule
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';

@Module({
 imports: [
    UserModule, // Import UserModule để sử dụng UserService
    PassportModule,
    ConfigModule, // Đảm bảo ConfigModule được import (thường là ở app.module)
    JwtModule.registerAsync({
        imports: [ConfigModule],
        inject: [ConfigService],
        useFactory: (configService: ConfigService) => ({
            // Cấu hình chung, nhưng sẽ bị ghi đè trong service
            secret: configService.get('JWT_SECRET'),
            signOptions: { expiresIn: configService.get('JWT_EXPIRATION') },
        }),
        }),
    ],
 providers: [AuthService, JwtStrategy, JwtRefreshStrategy],
 controllers: [AuthController],
})
export class AuthModule {}
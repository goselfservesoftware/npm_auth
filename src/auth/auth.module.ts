// auth.module.ts

import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config'; // Import ConfigModule
import { RolesGuard } from './role.guard';


@Module({
  imports: [
    ConfigModule.forRoot(), // Ensure ConfigModule is imported
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET, // It's better to use ConfigService here
    }),
  ],
  controllers: [],
  providers: [AuthService, JwtStrategy,RolesGuard],
  exports: [AuthService, JwtModule, PassportModule],
})
export class AuthModule {}

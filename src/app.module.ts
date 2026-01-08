// app.module.ts

import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config'; // Import ConfigModule
import { AuthService } from './auth/auth.service';
import { JwtStrategy } from './auth/jwt.strategy';
import { RolesGuard } from './auth/role.guard';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    ConfigModule.forRoot(),
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET, // It's better to use ConfigService here
    }), // Load environment variables
    AuthModule
  ],
  controllers: [AppController,],
  providers: [AuthService, JwtStrategy,RolesGuard,AppService],

})
export class AppModule {}

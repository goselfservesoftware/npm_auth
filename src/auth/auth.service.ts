

import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ERROR_MESSAGES } from './error-message';

@Injectable()
export class AuthService {
  private decodedToken: any;
  private secretKey: string;

  constructor(
    private jwtService: JwtService,
    private configService: ConfigService
  ) {
    this.secretKey = this.configService.get<string>('JWT_SECRET');
  }

  private extractToken(token: string): void {
    if (!token) {
      throw new HttpException(ERROR_MESSAGES.TOKEN_NOT_PROVIDED, HttpStatus.BAD_REQUEST);
    }

    try {
      this.decodedToken = this.jwtService.verify(token, { secret: this.secretKey });
      console.log('Decoded Token:', this.decodedToken);
    } catch (error) {
      console.error('Token verification error:', error.message);
      if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
        throw new HttpException(ERROR_MESSAGES.INVALID_TOKEN, HttpStatus.UNAUTHORIZED);
      } else {
        throw new HttpException(ERROR_MESSAGES.INVALID_TOKEN, HttpStatus.UNAUTHORIZED);
      }
    }
  }

  async getDecodedToken(token: string): Promise<any> {
    this.extractToken(token);
    return this.decodedToken;
  }

  async authorizeClaimBased(requiredPermissions: { [resource: string]: { read?: boolean; write?: boolean } }): Promise<boolean> {
    if (!this.decodedToken || !this.decodedToken.role || !this.decodedToken.roleAccess) {
      throw new HttpException(ERROR_MESSAGES.UNAUTHORIZED_ACCESS, HttpStatus.FORBIDDEN);
    }

    const userPermissions = this.decodedToken.roleAccess;
    console.log('User Permissions:', userPermissions);

    // Dynamically verify required permissions
    for (const [resource, requiredPermission] of Object.entries(requiredPermissions)) {
      const userPermission = userPermissions[resource];
      if (!userPermission) {
        throw new HttpException(`No role access for resource: ${resource}`, HttpStatus.FORBIDDEN);
      }

      if (
        (requiredPermission.read !== undefined && userPermission.read !== requiredPermission.read) ||
        (requiredPermission.write !== undefined && userPermission.write !== requiredPermission.write)
      ) {
        throw new HttpException(
          `Unauthorized access for resource ${resource}. Required permissions: ${JSON.stringify(requiredPermission)}`,
          HttpStatus.FORBIDDEN
        );
      }
    }

    return true;
  }

  async authorize(token: string, requiredPermissions: { [resource: string]: { read?: boolean; write?: boolean } }): Promise<boolean> {
    this.extractToken(token);
    return this.authorizeClaimBased(requiredPermissions);
  }
}

import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthService } from './auth.service';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector, private authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Retrieve metadata for roles and access
    const roles = this.reflector.get<string[]>('roles', context.getHandler());
    const access = this.reflector.get<{ resource: string; permissions: { read?: boolean; write?: boolean } }>('access', context.getHandler());

    // Ensure both roles and access are defined, otherwise throw an error
    if (!roles) {
      throw new ForbiddenException('Role metadata must be provided');
    }
    if (!access) {
      throw new ForbiddenException('Access metadata must be provided');
    }

    const request = context.switchToHttp().getRequest();
    const authHeader = request.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new ForbiddenException('Authorization header is missing or invalid');
    }

    const token = authHeader.split(' ')[1]; // Extract the token after 'Bearer'

    if (!token) {
      throw new ForbiddenException('Token is missing');
    }

    try {
      // Decode and validate the token
      const user = await this.authService.getDecodedToken(token);

      // Role check
      if (roles && !roles.includes(user.role)) {
        throw new ForbiddenException('User does not have the required role');
      }

      // Access check for both read and write permissions
      const userPermissions = user.roleAccess[access.resource];
      if (!userPermissions) {
        throw new ForbiddenException('User does not have access to this resource');
      }

      // Ensure read and write are explicitly defined (must be true or false)
      const { read, write } = access.permissions;
      
      if (read === undefined || write === undefined) {
        throw new ForbiddenException('Both read and write permissions must be explicitly defined as true or false');
      }

      // Check if the user has the required permissions
      if (userPermissions.read !== read || userPermissions.write !== write) {
        throw new ForbiddenException('User does not have the required permissions');
      }

      return true;
    } catch (error) {
      console.error('Authorization error:', error.message);
      throw new ForbiddenException('Authorization error');
    }
  }
}

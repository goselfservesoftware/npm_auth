// role.decorator.ts

import { SetMetadata } from '@nestjs/common';
import { Role, RoleAccess } from './role.enum';

// Decorator to set roles for route handlers
export const Roles = (...roles: Role[]) => SetMetadata('roles', roles);

// Decorator to set access permissions for route handlers
export const Access = (resource: keyof RoleAccess, permissions: { read?: boolean; write?: boolean }) =>
  SetMetadata('access', { resource, permissions });

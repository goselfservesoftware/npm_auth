// role.enum.ts

export type Role = string; // Use string to allow for flexible role names

export interface RoleAccess {
  [key: string]: {
    read: boolean;
    write: boolean;
  };
}

export interface RolePermissions {
  [key: string]: RoleAccess;
}

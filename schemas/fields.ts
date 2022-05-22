import { checkbox } from '@keystone-next/fields';

export const permissionFields = {
  canManageProducts: checkbox({
    defaultValue: true,
    label: 'User can Update and delete any product',
  }),
  canSeeOtherUsers: checkbox({
    defaultValue: true,
    label: 'User can query other users',
  }),
  canManageUsers: checkbox({
    defaultValue: true,
    label: 'User can Edit other users',
  }),
  canManageRoles: checkbox({
    defaultValue: true,
    label: 'User can CRUD roles',
  }),
  canManageCart: checkbox({
    defaultValue: true,
    label: 'User can see and manage cart and cart items',
  }),
  canManageOrders: checkbox({
    defaultValue: true,
    label: 'User can see and manage orders',
  }),
};

export type Permission = keyof typeof permissionFields;

export const permissionsList: Permission[] = Object.keys(
  permissionFields
) as Permission[];

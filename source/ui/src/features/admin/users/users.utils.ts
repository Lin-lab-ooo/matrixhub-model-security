import type { User } from '@matrixhub/api-ts/v1alpha1/user.pb'

export function getUserRowId(user: User) {
  return String(user.id ?? user.username ?? user.email ?? '-')
}

export function getUserDisplayName(user: User) {
  return user.username ?? user.email ?? `#${user.id ?? '-'}`
}

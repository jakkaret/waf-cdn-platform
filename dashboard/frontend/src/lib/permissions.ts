// Platform-level permission helpers (role-3 plan, Phase 1 frontend).
//
// The plan renames the platform roles: "admin" becomes "operator" and
// "viewer" becomes "user". Until the backend migration has run everywhere,
// the legacy "admin" value still means operator, so a deploy/migration order
// mismatch never locks an operator out.
type RoleCarrier = { role?: string | null } | null | undefined

const OPERATOR_ROLES = new Set(['operator', 'admin'])

export function isOperator(user: RoleCarrier): boolean {
  return !!user?.role && OPERATOR_ROLES.has(user.role)
}

// Human label for the platform role, shown instead of the raw stored value.
export function platformRoleLabel(user: RoleCarrier): string {
  return isOperator(user) ? 'Platform operator' : 'User'
}

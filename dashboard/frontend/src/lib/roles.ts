// Role names shown in the UI (2026-10-17). Stored values are unchanged:
// platform users.role is 'admin' | 'viewer'; origin roles are the creator
// (admin_user_id), editor_user_ids and viewer_user_ids.
//   Platform: Support (admin) | User (viewer)
//   Origin:   Owner > Editor > Viewer

export type PlatformRole = 'admin' | 'viewer'
export type OriginRole = 'owner' | 'editor' | 'viewer'

export const PLATFORM_ROLE_LABEL: Record<PlatformRole, string> = {
  admin: 'Support',
  viewer: 'User',
}

export const ORIGIN_ROLE_LABEL: Record<OriginRole, string> = {
  owner: 'Owner',
  editor: 'Editor',
  viewer: 'Viewer',
}

export function platformRoleLabel(role: string | undefined): string {
  return PLATFORM_ROLE_LABEL[role as PlatformRole] ?? 'User'
}

type OriginMembers = { admin_user_id?: string; editor_user_ids?: string[]; viewer_user_ids?: string[] }

export function originRoleOf(origin: OriginMembers | null | undefined, userId: string | undefined): OriginRole | null {
  if (!origin || !userId) return null
  if (origin.admin_user_id === userId) return 'owner'
  if ((origin.editor_user_ids ?? []).includes(userId)) return 'editor'
  if ((origin.viewer_user_ids ?? []).includes(userId)) return 'viewer'
  return null
}

// Owner: everything. Editor: day-to-day changes. Viewer: read only.
export const canEditOrigin = (r: OriginRole | null) => r === 'owner' || r === 'editor'
export const canManageOrigin = (r: OriginRole | null) => r === 'owner'

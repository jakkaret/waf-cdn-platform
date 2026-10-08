// Single source for the OWASP CRS version shown in the UI.
// TODO(backend): GET /api/system/status exposes no per-node CRS version.
// Once it does, read it from there and delete this constant. Value matches
// the CRS version pinned in the core image (verification ledger F-005).
export const CRS_VERSION = '4.25.1'

import React, { useState, useRef, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { getOrigins } from '../../api/origins'
import { Origin } from '../../types'
import { useOriginFilterStore } from '../../store/originFilterStore'
import { useAuthStore } from '../../store/authStore'
import { Globe, Shield, ChevronDown, Check, Server, Plus } from 'lucide-react'
import toast from 'react-hot-toast'

export const OriginSelector: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const { selectedOrigin, selectedOriginLabel, setSelectedOrigin } = useOriginFilterStore()
  const { user } = useAuthStore()

  // Fetch active origins belonging strictly to current logged-in user
  const { data } = useQuery({
    queryKey: ['origins-selector-list', user?.user_id],
    queryFn: () => getOrigins().then((r) => r.data?.origins || []).catch(() => []),
    refetchInterval: 10000,
    enabled: !!user,
  })

  // Safe array normalization
  const rawList = Array.isArray(data) ? data : (data as any)?.origins || []
  const userOrigins: Origin[] = Array.isArray(rawList) ? rawList : []

  // Filter active origins
  const activeUserOrigins = userOrigins.filter(
    (o) => o && (o.status || '').toLowerCase() !== 'archived' && (o.status || '').toLowerCase() !== 'deleted'
  )

  const isUserAdmin = user?.role === 'admin'

  // Available origins for this tenant
  const allAvailableOrigins = activeUserOrigins.map((uo) => ({
    id: uo.origin_id || (uo as any).id || `custom-${uo.ip}`,
    label: uo.label || uo.ip,
    ip: uo.ip,
    port: uo.port || 80,
    is_tunnel: (uo as any).is_tunnel || false,
  }))

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleSelect = (originKey: string, label: string) => {
    setSelectedOrigin(originKey || 'ALL', label || 'All Managed Origins')
    setIsOpen(false)
    toast.success(`Switched view to: ${label}`, {
      icon: originKey === 'ALL' ? '🌐' : '🛡️',
      duration: 2000,
    })
  }

  const hasOrigins = allAvailableOrigins.length > 0
  const triggerLabel = hasOrigins
    ? selectedOrigin === 'ALL'
      ? `All My Origins (${allAvailableOrigins.length})`
      : selectedOriginLabel || 'Selected Origin'
    : 'No Origins Added'

  return (
    <div className="relative font-mono" ref={dropdownRef}>
      {/* Selector Trigger Button */}
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className={`flex items-center gap-2 px-3 py-1.8 rounded-xl border text-[12px] font-semibold transition-all cursor-pointer shadow-sm ${
          selectedOrigin !== 'ALL'
            ? 'bg-indigo-600/15 border-indigo-500/40 text-indigo-300 hover:bg-indigo-600/25 hover:border-indigo-500/60'
            : 'bg-[var(--bg-surface)] border-[var(--bg-border)] text-[var(--text-primary)] hover:border-[var(--bg-border-hover)] hover:bg-[var(--bg-hover)]'
        }`}
        title="Filter dashboard telemetry & logs by Web Origin"
      >
        <div className="flex items-center gap-1.5 truncate max-w-[170px] sm:max-w-[220px]">
          {selectedOrigin === 'ALL' ? (
            <Globe size={14} className="text-orange-500 shrink-0" />
          ) : (
            <Shield size={14} className="text-indigo-400 shrink-0" />
          )}
          <span className="truncate">{triggerLabel}</span>
        </div>
        <ChevronDown
          size={13}
          className={`text-[var(--text-muted)] transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`}
        />
      </button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div className="absolute left-0 sm:right-0 sm:left-auto top-full mt-2 w-72 rounded-2xl bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] shadow-xl z-50 overflow-hidden animate-fade-in divide-y divide-[var(--bg-border-subtle)]">
          {/* Header */}
          <div className="px-3.5 py-2.5 bg-[var(--bg-primary)]/50 flex justify-between items-center">
            <span className="text-[10.5px] font-bold uppercase tracking-wider text-[var(--text-muted)] flex items-center gap-1.5">
              <Server size={12} className="text-orange-500" />
              My Web Origins
            </span>
            <Link
              to="/origins"
              onClick={() => setIsOpen(false)}
              className="text-[10px] text-orange-500 hover:underline flex items-center gap-0.5"
            >
              <Plus size={10} />
              Manage
            </Link>
          </div>

          {/* Options List */}
          <div className="max-h-64 overflow-y-auto p-1.5 space-y-1">
            {/* Option 1: ALL ORIGINS */}
            <button
              onClick={() =>
                handleSelect(
                  'ALL',
                  hasOrigins ? `All My Origins (${allAvailableOrigins.length})` : 'All Web Origins'
                )
              }
              className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-[12px] font-medium transition-all text-left cursor-pointer ${
                selectedOrigin === 'ALL'
                  ? 'bg-orange-500/15 text-orange-400 font-bold border border-orange-500/30'
                  : 'text-[var(--text-primary)] hover:bg-[var(--bg-hover)]'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <div className="w-6 h-6 rounded-lg bg-orange-500/15 flex items-center justify-center text-orange-500">
                  <Globe size={13} />
                </div>
                <div>
                  <p className="m-0 font-bold leading-none text-[12px]">
                    {hasOrigins ? 'All My Origins (ทั้งหมด)' : 'All Web Origins'}
                  </p>
                  <p className="m-0 text-[10px] text-[var(--text-muted)] mt-1">
                    {hasOrigins
                      ? `Aggregated telemetry for ${allAvailableOrigins.length} origins`
                      : 'No origin servers added yet'}
                  </p>
                </div>
              </div>
              {selectedOrigin === 'ALL' && <Check size={14} className="text-orange-500 shrink-0" />}
            </button>

            {/* User Specific Origins */}
            {allAvailableOrigins.length > 0 ? (
              allAvailableOrigins.map((origin) => {
                const isSelected = selectedOrigin === origin.ip || selectedOrigin === origin.id

                return (
                  <button
                    key={origin.id}
                    onClick={() => handleSelect(origin.ip, origin.label)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-[12px] transition-all text-left cursor-pointer ${
                      isSelected
                        ? 'bg-indigo-600/15 text-indigo-300 font-bold border border-indigo-500/30'
                        : 'text-[var(--text-primary)] hover:bg-[var(--bg-hover)]'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 truncate">
                      <div className="w-6 h-6 rounded-lg bg-indigo-500/15 flex items-center justify-center text-indigo-400 shrink-0">
                        <Shield size={13} />
                      </div>
                      <div className="truncate">
                        <p className="m-0 font-bold leading-none text-[12px] truncate">{origin.label}</p>
                        <p className="m-0 text-[10px] text-[var(--text-muted)] mt-1 truncate">
                          {origin.ip}:{origin.port}
                        </p>
                      </div>
                    </div>
                    {isSelected && <Check size={14} className="text-indigo-400 shrink-0 ml-2" />}
                  </button>
                )
              })
            ) : (
              <div className="p-3 text-center text-[11px] text-[var(--text-muted)]">
                <p className="m-0 mb-2">You have not created any origin servers yet.</p>
                <Link
                  to="/origins"
                  onClick={() => setIsOpen(false)}
                  className="inline-flex items-center gap-1 px-3 py-1 bg-orange-500 hover:bg-orange-600 text-white rounded-lg text-[11px] font-bold transition-colors"
                >
                  <Plus size={12} />
                  Add Origin Server
                </Link>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export default OriginSelector

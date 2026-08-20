import React, { useState } from 'react'
import { toast } from 'react-hot-toast'
import { Modal } from './ui/Modal'
import { Button } from './ui/Button'
import { createOrigin } from '../api/origins'

interface AddOriginModalProps {
  open: boolean
  onClose: () => void
  onSuccess: () => void
}

export const AddOriginModal: React.FC<AddOriginModalProps> = ({ open, onClose, onSuccess }) => {
  const [label, setLabel] = useState('')
  const [ip, setIp] = useState('')
  const [port, setPort] = useState(80)
  const [loading, setLoading] = useState(false)
  const [errors, setErrors] = useState<Record<string, string>>({})

  const validate = () => {
    const newErrors: Record<string, string> = {}
    if (!label.trim()) newErrors.label = 'Label is required'

    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/
    const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
    const trimmedTarget = ip.trim()

    if (!trimmedTarget) {
      newErrors.ip = 'IP Address or Domain Hostname is required'
    } else if (
      !ipRegex.test(trimmedTarget) &&
      !domainRegex.test(trimmedTarget) &&
      trimmedTarget !== 'localhost'
    ) {
      newErrors.ip =
        'Enter a valid IPv4 address or Domain Hostname (e.g. 192.168.1.100 or tunnel.trycloudflare.com)'
    }

    if (port < 1 || port > 65535) newErrors.port = 'Port must be between 1 and 65535'

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!validate()) return

    setLoading(true)
    try {
      await createOrigin({ label, ip, port })
      toast.success('Origin pool added successfully!')
      setLabel('')
      setIp('')
      setPort(80)
      onSuccess()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to add origin')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal open={open} onClose={onClose} title="Add Origin Server Pool">
      <form onSubmit={handleSubmit} className="space-y-4 text-[12.5px]">
        <div>
          <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1">
            Server Name / Label
          </label>
          <input
            type="text"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            className="w-full dash-input font-mono"
            placeholder="e.g. Production Web App"
          />
          {errors.label && <p className="mt-1 text-[11px] font-mono text-red-500">{errors.label}</p>}
        </div>

        <div>
          <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1">
            Upstream IPv4 or Domain Hostname
          </label>
          <input
            type="text"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            className="w-full dash-input font-mono"
            placeholder="e.g. 192.168.1.100 or tunnel.trycloudflare.com"
          />
          {errors.ip && <p className="mt-1 text-[11px] font-mono text-red-500">{errors.ip}</p>}
        </div>

        <div>
          <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1">
            HTTP Port (1 - 65535)
          </label>
          <input
            type="number"
            value={port}
            onChange={(e) => setPort(parseInt(e.target.value, 10) || 0)}
            className="w-full dash-input font-mono"
            placeholder="80"
          />
          {errors.port && <p className="mt-1 text-[11px] font-mono text-red-500">{errors.port}</p>}
        </div>

        <div className="pt-3 border-t border-[var(--bg-border)] flex justify-end gap-2.5">
          <Button variant="ghost" onClick={onClose} type="button">
            Cancel
          </Button>
          <Button variant="brand" type="submit" isLoading={loading}>
            Save & Connect Origin
          </Button>
        </div>
      </form>
    </Modal>
  )
}

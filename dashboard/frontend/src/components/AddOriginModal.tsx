import React, { useState } from 'react';
import { toast } from 'react-hot-toast';
import { Modal } from './ui/Modal';
import { Button } from './ui/Button';
import { createOrigin } from '../api/origins';

interface AddOriginModalProps {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const AddOriginModal: React.FC<AddOriginModalProps> = ({ open, onClose, onSuccess }) => {
  const [label, setLabel] = useState('');
  const [ip, setIp] = useState('');
  const [port, setPort] = useState(80);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const validate = () => {
    const newErrors: Record<string, string> = {};
    if (!label.trim()) newErrors.label = 'Label is required';
    
    // IPv4 validation
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipRegex.test(ip)) {
      newErrors.ip = 'Valid IPv4 address is required';
    } else {
      const parts = ip.split('.');
      if (parts.some(p => parseInt(p, 10) > 255)) {
        newErrors.ip = 'Valid IPv4 address is required';
      }
    }
    
    if (port < 1 || port > 65535) newErrors.port = 'Port must be between 1 and 65535';
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;

    setLoading(true);
    try {
      await createOrigin({ label, ip, port });
      toast.success('Origin added successfully!');
      
      // Reset form
      setLabel('');
      setIp('');
      setPort(80);
      
      onSuccess();
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to add origin');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal open={open} onClose={onClose} title="Add New Origin">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-text-primary mb-1">
            Label
          </label>
          <input
            type="text"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            className={`w-full px-3 py-2 border rounded-lg bg-bg-surface2 text-text-primary focus:outline-none focus:ring-1 transition-colors ${
              errors.label ? 'border-[#fc8181] focus:ring-[#fc8181]' : 'border-bg-border focus:border-accent focus:ring-accent'
            }`}
            placeholder="e.g. Production API"
          />
          {errors.label && <p className="mt-1 text-sm text-[#fc8181]">{errors.label}</p>}
        </div>

        <div>
          <label className="block text-sm font-medium text-text-primary mb-1">
            IP Address
          </label>
          <input
            type="text"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            className={`w-full px-3 py-2 border rounded-lg bg-bg-surface2 text-text-primary focus:outline-none focus:ring-1 transition-colors ${
              errors.ip ? 'border-[#fc8181] focus:ring-[#fc8181]' : 'border-bg-border focus:border-accent focus:ring-accent'
            }`}
            placeholder="e.g. 192.168.1.100"
          />
          {errors.ip && <p className="mt-1 text-sm text-[#fc8181]">{errors.ip}</p>}
        </div>

        <div>
          <label className="block text-sm font-medium text-text-primary mb-1">
            Port
          </label>
          <input
            type="number"
            value={port}
            onChange={(e) => setPort(parseInt(e.target.value) || 0)}
            className={`w-full px-3 py-2 border rounded-lg bg-bg-surface2 text-text-primary focus:outline-none focus:ring-1 transition-colors ${
              errors.port ? 'border-[#fc8181] focus:ring-[#fc8181]' : 'border-bg-border focus:border-accent focus:ring-accent'
            }`}
            placeholder="80"
          />
          {errors.port && <p className="mt-1 text-sm text-[#fc8181]">{errors.port}</p>}
        </div>

        <div className="pt-4 flex justify-end gap-3">
          <Button variant="secondary" onClick={onClose} type="button">
            Cancel
          </Button>
          <Button variant="primary" type="submit" isLoading={loading}>
            Add Origin
          </Button>
        </div>
      </form>
    </Modal>
  );
};

import React, { useState } from 'react';
import { toast } from 'react-hot-toast';
import { DnsInstructions } from './DnsInstructions';
import { Button } from './ui/Button';
import { Modal } from './ui/Modal';
import { LoadingSpinner } from './ui/LoadingSpinner';
import { createDomain, verifyDomain } from '../api/domains';
import { Domain, DnsInstructions as DnsInstructionsType } from '../types';

interface DomainSetupWizardProps {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
  originId: string;
}

type WizardStep = 'enter_domain' | 'dns_instructions' | 'verify_dns' | 'done' | 'failed';

export const DomainSetupWizard: React.FC<DomainSetupWizardProps> = ({
  open,
  onClose,
  onSuccess,
  originId,
}) => {
  const [step, setStep] = useState<WizardStep>('enter_domain');
  const [domainName, setDomainName] = useState('');
  const [domainNameError, setDomainNameError] = useState('');
  const [createdDomain, setCreatedDomain] = useState<Domain | null>(null);
  const [dnsInstructions, setDnsInstructions] = useState<DnsInstructionsType | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [verifyError, setVerifyError] = useState('');

  const validateDomain = (value: string) => {
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!value.trim()) return 'Domain name is required';
    if (!domainRegex.test(value)) return 'Please enter a valid domain name (e.g. example.com)';
    return '';
  };

  const handleCreateDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    const error = validateDomain(domainName);
    if (error) {
      setDomainNameError(error);
      return;
    }

    setIsLoading(true);
    try {
      const res = await createDomain(originId, { domain_name: domainName });
      setCreatedDomain(res.data.domain);
      setDnsInstructions(res.data.dns_instructions);
      setStep('dns_instructions');
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to add domain');
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerifyDns = async () => {
    if (!createdDomain) return;
    setIsLoading(true);
    setVerifyError('');
    try {
      const res = await verifyDomain(originId, createdDomain.domain_id);
      if (res.data.status === 'verified') {
        setStep('done');
        toast.success('Domain verified successfully!');
      } else {
        setVerifyError(res.data.message || 'DNS records not found yet. Please wait a few minutes and try again.');
      }
    } catch (err: any) {
      setVerifyError(err.response?.data?.detail || 'Verification failed. Check your DNS records and try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleClose = () => {
    // Reset state when closing
    setStep('enter_domain');
    setDomainName('');
    setDomainNameError('');
    setCreatedDomain(null);
    setDnsInstructions(null);
    setVerifyError('');
    onClose();
  };

  const handleDone = () => {
    onSuccess();
    handleClose();
  };

  const STEPS = ['Enter Domain', 'DNS Records', 'Verify DNS', 'Complete'];
  const stepIndex = {
    enter_domain: 0,
    dns_instructions: 1,
    verify_dns: 2,
    done: 3,
    failed: 2,
  }[step];

  const titleMap: Record<WizardStep, string> = {
    enter_domain: 'Add Custom Domain',
    dns_instructions: 'Configure DNS Records',
    verify_dns: 'Verify DNS Propagation',
    done: '🎉 Domain Added Successfully',
    failed: 'Verification Failed',
  };

  return (
    <Modal open={open} onClose={handleClose} title={titleMap[step]}>
      {/* Stepper */}
      <div className="flex items-center gap-0 mb-6">
        {STEPS.map((label, index) => (
          <React.Fragment key={label}>
            <div className="flex flex-col items-center flex-1">
              <div
                className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold border-2 transition-all ${
                  index < stepIndex
                    ? 'bg-success border-success text-white'
                    : index === stepIndex
                    ? 'bg-accent border-accent text-white shadow-[0_0_12px_rgba(102,126,234,0.5)]'
                    : 'bg-bg-surface2 border-bg-border text-text-muted'
                }`}
              >
                {index < stepIndex ? (
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                ) : (
                  index + 1
                )}
              </div>
              <span className={`text-[10px] mt-1 font-medium ${index === stepIndex ? 'text-accent' : index < stepIndex ? 'text-success' : 'text-text-muted'}`}>
                {label}
              </span>
            </div>
            {index < STEPS.length - 1 && (
              <div className={`h-0.5 flex-1 -mt-4 transition-all ${index < stepIndex ? 'bg-success' : 'bg-bg-border'}`} />
            )}
          </React.Fragment>
        ))}
      </div>

      {/* Step 1: Enter Domain */}
      {step === 'enter_domain' && (
        <form onSubmit={handleCreateDomain} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-text-primary mb-1">
              Domain Name
            </label>
            <input
              type="text"
              value={domainName}
              onChange={(e) => {
                setDomainName(e.target.value);
                if (domainNameError) setDomainNameError('');
              }}
              className={`w-full px-3 py-2.5 border rounded-lg bg-bg-surface2 text-text-primary focus:outline-none focus:ring-1 transition-colors text-sm ${
                domainNameError ? 'border-danger focus:ring-danger' : 'border-bg-border focus:border-accent focus:ring-accent'
              }`}
              placeholder="e.g. example.com or sub.example.com"
              autoFocus
            />
            {domainNameError && <p className="mt-1 text-xs text-danger">{domainNameError}</p>}
            <p className="mt-2 text-xs text-text-muted">
              After adding, you'll need to configure DNS records at your domain registrar.
            </p>
          </div>
          <div className="pt-2 flex justify-end gap-3">
            <Button variant="secondary" type="button" onClick={handleClose}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" isLoading={isLoading}>
              Continue
            </Button>
          </div>
        </form>
      )}

      {/* Step 2: DNS Instructions */}
      {step === 'dns_instructions' && dnsInstructions && (
        <div className="space-y-4">
          <p className="text-sm text-text-muted">
            Add these DNS records at your domain registrar for{' '}
            <span className="text-accent font-mono font-medium">{domainName}</span>
          </p>
          <DnsInstructions instructions={dnsInstructions} />
          <div className="rounded-lg bg-[#f6ad55]/10 border border-[#f6ad55]/20 p-3 text-xs text-[#f6ad55]">
            ⚠ DNS changes may take up to 24 hours to propagate globally. Usually it's faster (5-30 min).
          </div>
          <div className="pt-2 flex justify-end gap-3">
            <Button variant="secondary" type="button" onClick={handleClose}>
              I'll do this later
            </Button>
            <Button variant="primary" onClick={() => setStep('verify_dns')}>
              I've added the records →
            </Button>
          </div>
        </div>
      )}

      {/* Step 3: Verify DNS */}
      {step === 'verify_dns' && (
        <div className="space-y-4">
          <p className="text-sm text-text-muted">
            Click "Verify Now" to check if DNS records have propagated for{' '}
            <span className="text-accent font-mono font-medium">{domainName}</span>
          </p>

          <div className="rounded-lg border border-bg-border bg-bg-surface2 p-4 space-y-3">
            <div className="flex items-center gap-3 text-sm">
              <div className="w-8 h-8 rounded-full bg-accent/10 flex items-center justify-center">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#667eea" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10" />
                  <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                </svg>
              </div>
              <div>
                <p className="text-text-primary font-medium">DNS Propagation Check</p>
                <p className="text-text-muted text-xs">Checking CNAME and TXT records</p>
              </div>
            </div>

            {verifyError && (
              <div className="rounded-md bg-danger/10 border border-danger/20 p-3 text-xs text-danger">
                ❌ {verifyError}
              </div>
            )}
          </div>

          <div className="pt-2 flex justify-end gap-3">
            <Button variant="secondary" type="button" onClick={() => setStep('dns_instructions')}>
              ← Back
            </Button>
            <Button variant="primary" onClick={handleVerifyDns} isLoading={isLoading}>
              {isLoading ? 'Checking...' : 'Verify Now'}
            </Button>
          </div>
        </div>
      )}

      {/* Step 4: Done */}
      {step === 'done' && (
        <div className="text-center space-y-4 py-4">
          <div className="w-16 h-16 rounded-full bg-success/15 border-2 border-success flex items-center justify-center mx-auto">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#68d391" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="20 6 9 17 4 12" />
            </svg>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-text-primary">Domain Verified!</h3>
            <p className="text-sm text-text-muted mt-1">
              <span className="text-accent font-mono">{domainName}</span> is now connected to your origin server.
            </p>
          </div>
          <p className="text-xs text-text-muted">
            SSL certificate provisioning will begin automatically. This may take a few minutes.
          </p>
          <div className="pt-2">
            <Button variant="primary" onClick={handleDone} className="w-full">
              Done
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
};

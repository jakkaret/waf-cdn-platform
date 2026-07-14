import React from 'react';
import { Modal } from './Modal';
import { Button } from './Button';

interface ConfirmDialogProps {
  open: boolean;
  title?: string;
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
  confirmText?: string;
  cancelText?: string;
  isDanger?: boolean;
}

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  open,
  title = 'Confirm Action',
  message,
  onConfirm,
  onCancel,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  isDanger = false,
}) => {
  return (
    <Modal open={open} onClose={onCancel} title={title}>
      <div className="text-text-primary mb-6">
        <p>{message}</p>
      </div>
      <div className="flex justify-end gap-3">
        <Button variant="secondary" onClick={onCancel}>
          {cancelText}
        </Button>
        <Button variant={isDanger ? 'danger' : 'primary'} onClick={onConfirm}>
          {confirmText}
        </Button>
      </div>
    </Modal>
  );
};

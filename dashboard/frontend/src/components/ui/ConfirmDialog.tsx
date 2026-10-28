import React from 'react';
import { Modal } from './Modal';
import { Button } from './Button';
import { useT } from '../../i18n';

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
  title,
  message,
  onConfirm,
  onCancel,
  confirmText,
  cancelText,
  isDanger = false,
}) => {
  const { t } = useT();
  return (
    <Modal open={open} onClose={onCancel} title={title ?? t('Confirm action', 'ยืนยันการดำเนินการ')}>
      <div className="text-text-primary mb-6">
        <p>{message}</p>
      </div>
      <div className="flex justify-end gap-3">
        <Button variant="secondary" onClick={onCancel}>
          {cancelText ?? t('Cancel', 'ยกเลิก')}
        </Button>
        <Button variant={isDanger ? 'danger' : 'primary'} onClick={onConfirm}>
          {confirmText ?? t('Confirm', 'ยืนยัน')}
        </Button>
      </div>
    </Modal>
  );
};

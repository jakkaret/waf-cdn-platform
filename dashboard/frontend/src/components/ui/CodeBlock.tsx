import React from 'react';

interface CodeBlockProps {
  code: string;
  language?: string;
  className?: string;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({ code, className = '' }) => {
  return (
    <div className={`relative rounded-lg overflow-hidden border border-bg-border bg-[#0d1117] ${className}`}>
      <div className="absolute top-0 right-0 p-2">
        <button 
          onClick={() => navigator.clipboard.writeText(code)}
          className="p-1.5 rounded-md bg-bg-surface2 text-text-muted hover:text-text-primary transition-colors hover:bg-bg-border"
          title="Copy code"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
          </svg>
        </button>
      </div>
      <pre className="p-4 overflow-x-auto text-sm text-text-primary font-mono leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  );
};

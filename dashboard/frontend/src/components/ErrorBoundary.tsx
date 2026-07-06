import React, { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center p-4">
          <div className="bg-surface p-8 rounded-xl border border-white/5 max-w-md w-full shadow-2xl">
            <div className="w-12 h-12 bg-danger/20 text-danger rounded-full flex items-center justify-center mb-4 text-2xl font-bold">
              !
            </div>
            <h1 className="text-2xl font-bold mb-2">Something went wrong</h1>
            <p className="text-text-muted mb-6">
              The application encountered an unexpected error. Please try refreshing the page.
            </p>
            {this.state.error && (
              <div className="bg-black/50 p-4 rounded-lg overflow-auto mb-6 text-sm font-mono text-danger/80">
                {this.state.error.message}
              </div>
            )}
            <button
              onClick={() => window.location.reload()}
              className="w-full bg-accent hover:bg-accent-hover text-white py-2 px-4 rounded-lg font-medium transition-colors"
            >
              Refresh Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

import { Component } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error('[ErrorBoundary] Caught error:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          height: '60vh',
          gap: '1.5rem',
          color: 'var(--text-muted)',
        }}>
          <AlertTriangle size={48} color="var(--accent-red, #ef4444)" />
          <div style={{ textAlign: 'center' }}>
            <h2 style={{ color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
              Panel crashed
            </h2>
            <p style={{ fontSize: '0.875rem', maxWidth: 400 }}>
              {this.state.error?.message || 'An unexpected error occurred.'}
            </p>
          </div>
          <button
            className="btn-primary"
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <RefreshCw size={16} />
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

import React from "react";

// Minimal placeholder for SecureOps ErrorBoundary
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ error, errorInfo });
    // Optionally log error to an external service here
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 32, textAlign: 'center', color: '#b71c1c' }}>
          <h2>Something went wrong.</h2>
          <pre style={{ color: '#b71c1c', background: '#fff0f0', padding: 16, borderRadius: 8, overflowX: 'auto' }}>
            {this.state.error && this.state.error.toString()}
            {this.state.errorInfo && <details style={{ whiteSpace: 'pre-wrap' }}>{this.state.errorInfo.componentStack}</details>}
          </pre>
        </div>
      );
    }
    return this.props.children;
  }
}

export default ErrorBoundary;

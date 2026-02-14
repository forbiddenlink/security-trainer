import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

/**
 * Error boundary to catch and handle React errors gracefully.
 * Particularly important for catching lazy loading failures when
 * users have stale cached chunks or network issues.
 */
export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Log error for debugging (in production, send to error tracking service)
    if (import.meta.env.DEV) {
      console.error("ErrorBoundary caught an error:", error, errorInfo);
    }
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="flex flex-col items-center justify-center h-64 text-center p-6">
          <AlertTriangle
            className="w-12 h-12 text-yellow-500 mb-4"
            aria-hidden="true"
          />
          <h2 className="text-xl font-semibold text-foreground mb-2">
            Something went wrong
          </h2>
          <p className="text-foreground/70 mb-4 max-w-md">
            {this.state.error?.message?.includes("Loading chunk")
              ? "A page failed to load. This can happen when the app was updated. Please refresh."
              : "An unexpected error occurred. Please try refreshing the page."}
          </p>
          <button
            onClick={this.handleRetry}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:opacity-90 transition-opacity"
            aria-label="Reload the page"
          >
            <RefreshCw className="w-4 h-4" aria-hidden="true" />
            Reload Page
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

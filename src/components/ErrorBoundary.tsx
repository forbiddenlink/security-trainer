import { Component, type ErrorInfo, type ReactNode } from "react";
import { RefreshCw } from "lucide-react";

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
        <div className="max-w-xl mx-auto py-16 px-6 text-left">
          <div className="ui-card ui-card-lg border-l-[3px] border-l-destructive">
            <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-destructive">
              System fault
            </p>
            <h2 className="font-display [font-stretch:75%] font-extrabold text-h2 mt-2 mb-3">
              Something went wrong
            </h2>
            <p className="text-body-sm text-muted-foreground mb-6 max-w-md">
              {this.state.error?.message?.includes("Loading chunk")
                ? "A page failed to load. This can happen when the app was updated. Please refresh."
                : "An unexpected error occurred. Please try refreshing the page."}
            </p>
            <button
              onClick={this.handleRetry}
              className="btn-signal"
              aria-label="Reload the page"
            >
              <RefreshCw className="w-4 h-4" aria-hidden="true" />
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

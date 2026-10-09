import React from "react";
import { cn } from "../../lib/cn";
import { Crosshair } from "lucide-react";

interface EmptyStateProps extends React.HTMLAttributes<HTMLDivElement> {
  title: string;
  description?: string;
  icon?: React.ReactNode;
  action?: React.ReactNode;
}

export const EmptyState = React.forwardRef<HTMLDivElement, EmptyStateProps>(
  ({ className, title, description, icon, action, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          "flex flex-col items-center justify-center text-center px-6 py-12",
          className,
        )}
        {...props}
      >
        <div className="relative w-16 h-16 rounded-[var(--radius-sm)] bg-card border border-border flex items-center justify-center mb-5 text-muted-foreground shadow-sm">
          {/* Subtle corner registration marks */}
          <span
            className="absolute top-1 left-1 w-1.5 h-1.5 border-t border-l border-muted-foreground/40"
            aria-hidden="true"
          />
          <span
            className="absolute top-1 right-1 w-1.5 h-1.5 border-t border-r border-muted-foreground/40"
            aria-hidden="true"
          />
          <span
            className="absolute bottom-1 left-1 w-1.5 h-1.5 border-b border-l border-muted-foreground/40"
            aria-hidden="true"
          />
          <span
            className="absolute bottom-1 right-1 w-1.5 h-1.5 border-b border-r border-muted-foreground/40"
            aria-hidden="true"
          />
          {icon ?? <Crosshair className="w-7 h-7" aria-hidden="true" />}
        </div>
        <span className="range-readout mb-2">TELEMETRY STANDBY</span>
        <h2 className="text-h3 mb-2">{title}</h2>
        {description && (
          <p className="text-muted-foreground text-body-sm max-w-md">
            {description}
          </p>
        )}
        {action && <div className="mt-6">{action}</div>}
      </div>
    );
  },
);

EmptyState.displayName = "EmptyState";

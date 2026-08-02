import React from "react";
import { cn } from "../../lib/cn";
import { Inbox } from "lucide-react";

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
        <div className="w-16 h-16 rounded-full bg-muted/60 border border-border/70 flex items-center justify-center mb-5 text-muted-foreground">
          {icon ?? <Inbox className="w-7 h-7" aria-hidden="true" />}
        </div>
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

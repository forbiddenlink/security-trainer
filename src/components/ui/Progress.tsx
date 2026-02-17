import React from "react";
import { cn } from "../../lib/cn";

interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value: number;
  min?: number;
  max?: number;
  indicatorClassName?: string;
}

export const Progress = React.forwardRef<HTMLDivElement, ProgressProps>(
  (
    { className, value, min = 0, max = 100, indicatorClassName, ...props },
    ref,
  ) => {
    const clampedValue = Math.min(Math.max(value, min), max);
    const width = ((clampedValue - min) / (max - min)) * 100;

    return (
      <div
        ref={ref}
        role="progressbar"
        aria-valuemin={min}
        aria-valuemax={max}
        aria-valuenow={clampedValue}
        className={cn(
          "h-1.5 w-full overflow-hidden rounded-full bg-muted",
          className,
        )}
        {...props}
      >
        <div
          className={cn(
            "h-full bg-primary transition-all duration-300",
            indicatorClassName,
          )}
          style={{ width: `${width}%` }}
        />
      </div>
    );
  },
);

Progress.displayName = "Progress";

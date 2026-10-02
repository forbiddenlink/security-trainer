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
        className={cn("h-1 w-full overflow-hidden bg-muted", className)}
        {...props}
      >
        <div
          className={cn(
            "h-full bg-primary transition-[width] duration-500 ease-[cubic-bezier(0.2,0.8,0.2,1)]",
            indicatorClassName,
          )}
          style={{ width: `${width}%` }}
        />
      </div>
    );
  },
);

Progress.displayName = "Progress";

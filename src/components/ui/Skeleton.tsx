import React from "react";
import { cn } from "../../lib/cn";

interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Rounded pill vs rectangular */
  rounded?: "sm" | "md" | "lg" | "full";
}

export const Skeleton = React.forwardRef<HTMLDivElement, SkeletonProps>(
  ({ className, rounded = "sm", ...props }, ref) => {
    const radius =
      rounded === "full"
        ? "rounded-full"
        : rounded === "lg"
          ? "rounded-[var(--radius-lg)]"
          : rounded === "md"
            ? "rounded-[var(--radius-md)]"
            : "rounded-[var(--radius-sm)]";

    return (
      <div
        ref={ref}
        className={cn(
          "animate-pulse bg-muted/80 border border-border/40",
          radius,
          className,
        )}
        aria-hidden="true"
        {...props}
      />
    );
  },
);

Skeleton.displayName = "Skeleton";

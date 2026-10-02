import React from "react";
import { cn } from "../../lib/cn";

type ChipTone = "default" | "primary" | "accent" | "warning" | "destructive";

interface ChipProps extends React.HTMLAttributes<HTMLSpanElement> {
  tone?: ChipTone;
}

const toneClasses: Record<ChipTone, string> = {
  default: "border-border text-muted-foreground",
  primary: "border-primary/50 text-primary",
  accent: "border-accent/50 text-accent",
  warning: "border-warning/50 text-warning",
  destructive: "border-destructive/50 text-destructive",
};

export const Chip = React.forwardRef<HTMLSpanElement, ChipProps>(
  ({ className, tone = "default", ...props }, ref) => {
    return (
      <span
        ref={ref}
        className={cn("ui-chip", toneClasses[tone], className)}
        {...props}
      />
    );
  },
);

Chip.displayName = "Chip";

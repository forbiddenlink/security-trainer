import React from "react";
import { cn } from "../../lib/cn";

type ChipTone = "default" | "primary" | "accent" | "warning" | "destructive";

interface ChipProps extends React.HTMLAttributes<HTMLSpanElement> {
  tone?: ChipTone;
}

const toneClasses: Record<ChipTone, string> = {
  default: "border-border bg-muted/60 text-muted-foreground",
  primary: "border-primary/35 text-primary bg-primary/8",
  accent: "border-accent/35 text-accent bg-accent/8",
  warning: "border-warning/35 text-warning bg-warning/8",
  destructive: "border-destructive/35 text-destructive bg-destructive/8",
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

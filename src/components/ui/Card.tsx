import React from "react";
import { cn } from "../../lib/cn";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  elevated?: boolean;
}

export const Card = React.forwardRef<HTMLDivElement, CardProps>(
  ({ className, elevated = false, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn("ui-card", elevated && "ui-card-elevated", className)}
        {...props}
      />
    );
  },
);

Card.displayName = "Card";

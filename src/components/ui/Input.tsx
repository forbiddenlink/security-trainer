import React from "react";
import { cn } from "../../lib/cn";

type InputProps = React.InputHTMLAttributes<HTMLInputElement>;

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, ...props }, ref) => {
    return (
      <input
        ref={ref}
        className={cn("ui-input w-full", className)}
        {...props}
      />
    );
  },
);

Input.displayName = "Input";

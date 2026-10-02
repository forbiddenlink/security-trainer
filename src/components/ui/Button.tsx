import React from "react";
import { cn } from "../../lib/cn";

type ButtonVariant =
  | "primary"
  | "secondary"
  | "outline"
  | "ghost"
  | "accent"
  | "warning"
  | "destructive"
  | "signal";

type ButtonSize = "sm" | "md" | "lg";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

const variantClasses: Record<ButtonVariant, string> = {
  primary: "bg-primary text-primary-foreground hover:bg-primary-hover",
  secondary:
    "border border-border bg-transparent text-foreground hover:border-foreground",
  outline: "border border-border text-foreground hover:border-foreground",
  signal: "bg-signal text-signal-ink border border-signal hover:brightness-105",
  ghost: "text-foreground hover:bg-muted/60",
  accent: "bg-accent text-accent-foreground hover:bg-accent/90",
  warning: "bg-warning text-black hover:bg-warning/90",
  destructive:
    "bg-destructive text-destructive-foreground hover:bg-destructive/90",
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: "h-9 px-3 text-sm",
  md: "h-11 px-4",
  lg: "h-12 px-6",
};

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    { className, variant = "primary", size = "md", type = "button", ...props },
    ref,
  ) => {
    return (
      <button
        ref={ref}
        type={type}
        className={cn(
          "inline-flex items-center justify-center gap-2 rounded-[var(--radius-sm)] font-semibold transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:pointer-events-none",
          variantClasses[variant],
          sizeClasses[size],
          className,
        )}
        {...props}
      />
    );
  },
);

Button.displayName = "Button";

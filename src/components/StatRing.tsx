import React from "react";
import { motion } from "framer-motion";

interface StatRingProps {
  value: number;
  max: number;
  /** SVG outer diameter in px */
  size?: number;
  strokeWidth?: number;
  /** Tailwind text-* class for the ring color (uses currentColor on stroke) */
  colorClass?: string;
  children?: React.ReactNode;
}

export const StatRing: React.FC<StatRingProps> = ({
  value,
  max,
  size = 72,
  strokeWidth = 5,
  colorClass = "text-primary",
  children,
}) => {
  const r = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * r;
  const progress = max > 0 ? Math.min(value / max, 1) : 0;
  const dashoffset = circumference * (1 - progress);

  return (
    <div
      className="relative flex-shrink-0"
      style={{ width: size, height: size }}
    >
      <svg
        width={size}
        height={size}
        aria-hidden="true"
        style={{ transform: "rotate(-90deg)" }}
      >
        {/* Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="currentColor"
          className="text-muted/50"
          strokeWidth={strokeWidth}
        />
        {/* Progress arc */}
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="currentColor"
          className={colorClass}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: dashoffset }}
          transition={{ duration: 1.2, ease: "easeOut" }}
        />
      </svg>
      {children && (
        <div className="absolute inset-0 flex items-center justify-center">
          {children}
        </div>
      )}
    </div>
  );
};

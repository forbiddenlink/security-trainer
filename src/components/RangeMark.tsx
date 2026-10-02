import React from "react";

interface RangeMarkProps {
  className?: string;
}

/** Brand mark: a reticle with one signal quadrant. Decorative. */
export const RangeMark: React.FC<RangeMarkProps> = ({ className }) => (
  <svg
    viewBox="0 0 32 32"
    fill="none"
    className={className}
    aria-hidden="true"
    focusable="false"
  >
    <rect x="0.5" y="0.5" width="31" height="31" rx="2" stroke="currentColor" />
    <circle cx="16" cy="16" r="9" stroke="currentColor" />
    <path d="M16 3v6M16 23v6M3 16h6M23 16h6" stroke="currentColor" />
    <path d="M16 7a9 9 0 0 1 9 9h-9z" fill="var(--color-signal)" />
    <circle cx="16" cy="16" r="1.5" fill="currentColor" />
  </svg>
);

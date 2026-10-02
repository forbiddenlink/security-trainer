import React from "react";

interface Readout {
  label: string;
  value: number | string;
}

interface RangeInstrumentProps {
  readouts: readonly Readout[];
  /** 0..1, how far the learner is through the catalog */
  progress: number;
  className?: string;
}

/**
 * Hero "test card": reticle line art carrying real catalog counts.
 * Decorative geometry is aria-hidden; the readouts are exposed as a list.
 */
export const RangeInstrument: React.FC<RangeInstrumentProps> = ({
  readouts,
  progress,
  className,
}) => {
  const pct = Math.round(Math.min(1, Math.max(0, progress)) * 100);
  const ticks = Array.from({ length: 21 }, (_, i) => i);
  const arc = 2 * Math.PI * 92;

  return (
    <figure
      className={`relative border border-border bg-card rounded-[var(--radius-md)] overflow-hidden ${className ?? ""}`}
    >
      <svg
        viewBox="0 0 400 300"
        className="w-full h-auto block text-border"
        aria-hidden="true"
        focusable="false"
      >
        {/* Frame grid */}
        {[100, 200, 300].map((x) => (
          <line
            key={`v${x}`}
            x1={x}
            y1="0"
            x2={x}
            y2="300"
            stroke="currentColor"
          />
        ))}
        {[75, 150, 225].map((y) => (
          <line
            key={`h${y}`}
            x1="0"
            y1={y}
            x2="400"
            y2={y}
            stroke="currentColor"
          />
        ))}
        {/* Reticle */}
        <circle
          cx="200"
          cy="150"
          r="92"
          fill="none"
          stroke="var(--color-foreground)"
          strokeOpacity="0.35"
        />
        <circle
          cx="200"
          cy="150"
          r="56"
          fill="none"
          stroke="var(--color-foreground)"
          strokeOpacity="0.25"
        />
        <circle
          cx="200"
          cy="150"
          r="92"
          fill="none"
          stroke="var(--color-primary)"
          strokeWidth="3"
          strokeDasharray={`${(arc * pct) / 100} ${arc}`}
          transform="rotate(-90 200 150)"
        />
        <path
          d="M200 46v28M200 226v28M96 150h28M276 150h28"
          stroke="var(--color-foreground)"
          strokeOpacity="0.6"
        />
        {/* Corner gauges */}
        <rect
          x="16"
          y="16"
          width="64"
          height="10"
          fill="none"
          stroke="var(--color-foreground)"
          strokeOpacity="0.4"
        />
        <rect
          x="16"
          y="16"
          width={Math.max(2, (64 * pct) / 100)}
          height="10"
          fill="var(--color-primary)"
        />
        <circle cx="356" cy="40" r="22" fill="none" stroke="currentColor" />
        <path d="M341 25l30 30M371 25l-30 30" stroke="currentColor" />
        <rect
          x="364"
          y="200"
          width="16"
          height="84"
          fill="none"
          stroke="currentColor"
        />
        {Array.from({ length: 7 }, (_, i) => (
          <line
            key={i}
            x1="364"
            x2="380"
            y1={212 + i * 12}
            y2={212 + i * 12}
            stroke="currentColor"
          />
        ))}
        {/* Bottom ruler */}
        {ticks.map((i) => (
          <line
            key={i}
            x1={20 + i * 14}
            x2={20 + i * 14}
            y1={i % 5 === 0 ? 270 : 276}
            y2="284"
            stroke="var(--color-foreground)"
            strokeOpacity={i % 5 === 0 ? 0.6 : 0.3}
          />
        ))}
        <text
          x="20"
          y="262"
          className="font-mono"
          fontSize="8"
          fill="var(--color-muted-foreground)"
          letterSpacing="1.5"
        >
          0%
        </text>
        <text
          x="300"
          y="262"
          className="font-mono"
          fontSize="8"
          fill="var(--color-muted-foreground)"
          letterSpacing="1.5"
          textAnchor="end"
        >
          100%
        </text>
        <text
          x="200"
          y="154"
          textAnchor="middle"
          className="font-mono"
          fontSize="11"
          fill="var(--color-foreground)"
          letterSpacing="2"
        >
          {pct}%
        </text>
        <text
          x="200"
          y="170"
          textAnchor="middle"
          className="font-mono"
          fontSize="7"
          fill="var(--color-muted-foreground)"
          letterSpacing="1.8"
        >
          CLEARED
        </text>
      </svg>
      <span className="scanline" aria-hidden="true" />
      <figcaption className="border-t border-border">
        <dl className="grid grid-cols-2 sm:grid-cols-4 divide-x divide-border">
          {readouts.map((r) => (
            <div key={r.label} className="px-3 py-3">
              <dt className="ui-label !text-[10px]">{r.label}</dt>
              <dd className="mt-1 font-display font-extrabold [font-stretch:75%] text-h3 leading-none tabular-nums">
                {r.value}
              </dd>
            </div>
          ))}
        </dl>
      </figcaption>
    </figure>
  );
};

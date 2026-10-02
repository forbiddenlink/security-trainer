import React from "react";

interface RuledSectionProps {
  index: string;
  label: string;
  id: string;
  title: string;
  aside?: React.ReactNode;
  children: React.ReactNode;
}

/** Numbered, hairline-ruled page section with a mono label rail. */
export const RuledSection: React.FC<RuledSectionProps> = ({
  index,
  label,
  id,
  title,
  aside,
  children,
}) => (
  <section className="section-rule" aria-labelledby={id}>
    <div className="section-rail">
      <span className="section-index">{index}</span>
      <span className="ui-label">{label}</span>
    </div>
    <div className="min-w-0">
      <div className="flex items-end justify-between gap-4 mb-5">
        <h2 id={id} className="text-h2">
          {title}
        </h2>
        {aside}
      </div>
      {children}
    </div>
  </section>
);

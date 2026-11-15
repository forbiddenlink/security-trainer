import React from "react";
import { Link } from "react-router-dom";

/** Shown for any URL the app does not define (instead of silently redirecting home). */
export const NotFound: React.FC = () => {
  return (
    <div className="max-w-3xl">
      <header className="pb-8">
        <p className="range-readout mb-3">
          <span className="range-dot" aria-hidden="true" />
          Error 404
        </p>
        <h1 className="text-display">Page not found</h1>
        <p className="mt-4 text-muted-foreground max-w-[60ch]">
          There is nothing at this address. Check the link, or head back to the
          dashboard.
        </p>
        <Link to="/" className="mt-6 inline-block underline underline-offset-4">
          Back to dashboard
        </Link>
      </header>
    </div>
  );
};

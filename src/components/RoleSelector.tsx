import React from "react";
import { useGameStore } from "../store/gameStore";
import { clsx } from "clsx";

import { ROLES } from "../data/roles";

/**
 * Compact role calibration: one row of pills. Choosing a role re-targets the
 * hero's first-mission button; nothing else is gated on it.
 */
export const RoleSelector: React.FC = () => {
  const userRole = useGameStore((s) => s.userRole);
  const setUserRole = useGameStore((s) => s.setUserRole);

  return (
    <fieldset className="min-w-0">
      <legend className="ui-label mb-3">Calibrate your track (optional)</legend>
      <div className="flex flex-wrap gap-2">
        {ROLES.map((role) => (
          <button
            key={role.id}
            type="button"
            aria-pressed={userRole === role.id}
            title={role.description}
            onClick={() =>
              setUserRole(userRole === role.id ? "skipped" : role.id)
            }
            className={clsx("filter-pill")}
          >
            {role.title}
          </button>
        ))}
      </div>
    </fieldset>
  );
};

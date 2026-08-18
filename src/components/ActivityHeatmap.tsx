import React, { useMemo } from "react";
import { useGameStore } from "../store/gameStore";

const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

/** Build a 52-week (364-day) grid of dates ending today. */
function buildWeekGrid(): { date: string; weekIdx: number; dayIdx: number }[] {
  const cells: { date: string; weekIdx: number; dayIdx: number }[] = [];
  const today = new Date();
  // Shift so grid ends on Saturday of current week
  const endDow = today.getDay(); // 0=Sun
  const daysBack = 364 + endDow; // go back far enough to fill 53 cols × 7 rows

  const start = new Date(today);
  start.setDate(today.getDate() - daysBack);
  // Align start to Sunday
  const startDow = start.getDay();
  start.setDate(start.getDate() - startDow);

  const cur = new Date(start);
  let col = 0;
  while (cur <= today) {
    const dow = cur.getDay(); // 0=Sun
    cells.push({
      date: cur.toISOString().split("T")[0],
      weekIdx: col,
      dayIdx: dow,
    });
    cur.setDate(cur.getDate() + 1);
    if (dow === 6) col++;
  }
  return cells;
}

/** Month label positions: find first cell of each month. */
function getMonthLabels(
  cells: ReturnType<typeof buildWeekGrid>,
): { label: string; weekIdx: number }[] {
  const seen = new Set<string>();
  const labels: { label: string; weekIdx: number }[] = [];
  for (const cell of cells) {
    const [, m] = cell.date.split("-");
    if (!seen.has(m)) {
      seen.add(m);
      labels.push({
        label: MONTHS[parseInt(m, 10) - 1],
        weekIdx: cell.weekIdx,
      });
    }
  }
  return labels;
}

export const ActivityHeatmap: React.FC = () => {
  const activityLog = useGameStore((s) => s.activityLog);
  const activitySet = useMemo(() => new Set(activityLog), [activityLog]);

  const cells = useMemo(() => buildWeekGrid(), []);
  const monthLabels = useMemo(() => getMonthLabels(cells), [cells]);
  const totalWeeks = useMemo(
    () => Math.max(...cells.map((c) => c.weekIdx)) + 1,
    [cells],
  );

  // Build grid: [weekIdx][dayIdx] = date string | null
  const grid = useMemo(() => {
    const g: (string | null)[][] = Array.from({ length: totalWeeks }, () =>
      Array(7).fill(null),
    );
    for (const c of cells) {
      g[c.weekIdx][c.dayIdx] = c.date;
    }
    return g;
  }, [cells, totalWeeks]);

  const totalActive = activitySet.size;

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-h4 flex items-center gap-2">
          <span className="range-dot" aria-hidden="true" />
          Activity Log
        </h3>
        <span className="text-body-sm text-muted-foreground">
          {totalActive} active day{totalActive !== 1 ? "s" : ""} in the last
          year
        </span>
      </div>

      <div className="overflow-x-auto">
        <div style={{ minWidth: `${totalWeeks * 13 + 32}px` }}>
          {/* Month labels */}
          <div className="flex mb-1 ml-8">
            {monthLabels.map(({ label, weekIdx }) => (
              <div
                key={label + weekIdx}
                className="text-[10px] text-muted-foreground"
                style={{
                  position: "relative",
                  left: `${weekIdx * 13}px`,
                  width: 0,
                  whiteSpace: "nowrap",
                }}
              >
                {label}
              </div>
            ))}
          </div>

          {/* Grid: rows = day of week (Sun–Sat), cols = weeks */}
          <div className="flex gap-1">
            {/* Day labels */}
            <div className="flex flex-col gap-[3px] mr-1">
              {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map(
                (day, i) => (
                  <div
                    key={day}
                    className="h-[10px] text-[9px] text-muted-foreground leading-none"
                    style={{ opacity: i % 2 === 1 ? 1 : 0 }}
                  >
                    {day}
                  </div>
                ),
              )}
            </div>

            {/* Week columns */}
            {grid.map((week, wIdx) => (
              <div key={wIdx} className="flex flex-col gap-[3px]">
                {week.map((date, dIdx) => {
                  const active = date !== null && activitySet.has(date);
                  const isToday =
                    date === new Date().toISOString().split("T")[0];
                  return (
                    <div
                      key={dIdx}
                      title={date ?? ""}
                      className={[
                        "w-[10px] h-[10px] rounded-[2px] transition-colors",
                        date === null
                          ? "opacity-0"
                          : active
                            ? "bg-accent"
                            : "bg-muted/60",
                        isToday && !active
                          ? "ring-1 ring-primary/60 ring-offset-0"
                          : "",
                      ]
                        .filter(Boolean)
                        .join(" ")}
                      aria-label={
                        date
                          ? `${date}: ${active ? "active" : "no activity"}`
                          : undefined
                      }
                    />
                  );
                })}
              </div>
            ))}
          </div>

          {/* Legend */}
          <div className="flex items-center gap-2 mt-2 justify-end">
            <span className="text-[10px] text-muted-foreground">Less</span>
            {[false, true].map((on) => (
              <div
                key={String(on)}
                className={`w-[10px] h-[10px] rounded-[2px] ${on ? "bg-accent" : "bg-muted/60"}`}
              />
            ))}
            <span className="text-[10px] text-muted-foreground">More</span>
          </div>
        </div>
      </div>
    </div>
  );
};

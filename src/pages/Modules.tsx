import React, { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import {
  ArrowRight,
  Check,
  Dices,
  Lock,
  Search,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { clsx } from "clsx";
import { MODULES } from "../data/modules";
import { useGameStore } from "../store/gameStore";
import { Button, EmptyState, Input, Progress } from "../components/ui";
import {
  estimateModuleMinutes,
  formatMinutes,
  getLessonMix,
  getModuleStatus,
  type ModuleStatus,
} from "../lib/moduleMeta";

const MODULE_CATEGORIES: Record<string, { label: string; category: string }> = {
  "owasp-intro": { label: "Web Security", category: "web-security" },
  "sql-injection": { label: "Web Security", category: "web-security" },
  "xss-basics": { label: "Web Security", category: "web-security" },
  "csrf-attacks": { label: "Web Security", category: "web-security" },
  clickjacking: { label: "Web Security", category: "web-security" },
  "idor-basics": { label: "Web Security", category: "web-security" },
  "sensitive-data-exposure": {
    label: "Web Security",
    category: "web-security",
  },
  "cors-misconfig": { label: "Web Security", category: "web-security" },
  "file-upload": { label: "Web Security", category: "web-security" },
  "security-misconfig": { label: "Web Security", category: "web-security" },
  "path-traversal": { label: "Web Security", category: "web-security" },
  "session-management": { label: "Web Security", category: "web-security" },
  "api-security": { label: "API & Backend", category: "api-backend" },
  "jwt-vulnerabilities": { label: "API & Backend", category: "api-backend" },
  "graphql-security": { label: "API & Backend", category: "api-backend" },
  "broken-auth": { label: "API & Backend", category: "api-backend" },
  "command-injection": { label: "API & Backend", category: "api-backend" },
  "ssrf-attacks": { label: "API & Backend", category: "api-backend" },
  "xxe-attacks": { label: "API & Backend", category: "api-backend" },
  "insecure-deserialization": {
    label: "API & Backend",
    category: "api-backend",
  },
  "oauth-security": { label: "API & Backend", category: "api-backend" },
  "business-logic": { label: "Advanced", category: "advanced" },
  "race-conditions": { label: "Advanced", category: "advanced" },
  "prototype-pollution": { label: "Advanced", category: "advanced" },
  "subdomain-takeover": { label: "Advanced", category: "advanced" },
  "websocket-security": { label: "Advanced", category: "advanced" },
  "vulnerable-components": { label: "Advanced", category: "advanced" },
  "logging-monitoring": { label: "Advanced", category: "advanced" },
  "ai-security": { label: "Advanced", category: "advanced" },
  "social-engineering": { label: "Advanced", category: "advanced" },
  "container-security": {
    label: "Infrastructure",
    category: "infrastructure",
  },
  "supply-chain-security": {
    label: "Infrastructure",
    category: "infrastructure",
  },
  "cloud-security": { label: "Infrastructure", category: "infrastructure" },
  "incident-response": {
    label: "Infrastructure",
    category: "infrastructure",
  },
  "phishing-awareness": { label: "Awareness", category: "awareness" },
  "password-data-hygiene": { label: "Awareness", category: "awareness" },
  "incident-reporting": { label: "Awareness", category: "awareness" },
  "safe-browsing-remote": { label: "Awareness", category: "awareness" },
  "gdpr-fundamentals": { label: "Compliance", category: "compliance" },
  "pci-dss-essentials": { label: "Compliance", category: "compliance" },
  "soc2-awareness": { label: "Compliance", category: "compliance" },
  "hipaa-basics": { label: "Compliance", category: "compliance" },
};

const CATEGORY_OPTIONS = [
  { value: "all", label: "All" },
  { value: "web-security", label: "Web Security" },
  { value: "api-backend", label: "API & Backend" },
  { value: "advanced", label: "Advanced" },
  { value: "infrastructure", label: "Infrastructure" },
  { value: "awareness", label: "Awareness" },
  { value: "compliance", label: "Compliance" },
] as const;

const LEVEL_OPTIONS = ["Beginner", "Intermediate", "Advanced"] as const;

const STATUS_OPTIONS: { value: ModuleStatus; label: string }[] = [
  { value: "new", label: "Not started" },
  { value: "in-progress", label: "In progress" },
  { value: "done", label: "Done" },
];

const SORT_OPTIONS = [
  { value: "catalog", label: "Catalog order" },
  { value: "shortest", label: "Shortest first" },
  { value: "xp", label: "Most XP" },
] as const;

type SortValue = (typeof SORT_OPTIONS)[number]["value"];

const opNumber = (id: string): string =>
  String(MODULES.findIndex((m) => m.id === id) + 1).padStart(2, "0");

const LEVEL_TONE: Record<string, string> = {
  Beginner: "text-accent border-accent/50",
  Intermediate: "text-warning border-warning/50",
  Advanced: "text-destructive border-destructive/50",
};

export const Modules: React.FC = () => {
  const completedModules = useGameStore((s) => s.completedModules);
  const completedLessons = useGameStore((s) => s.completedLessons);
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [showRefine, setShowRefine] = useState(false);

  const searchQuery = params.get("q") ?? "";
  const selectedCategory = params.get("cat") ?? "all";
  const selectedLevel = params.get("level") ?? "";
  const selectedStatus = (params.get("status") ?? "") as ModuleStatus | "";
  const sort = (params.get("sort") ?? "catalog") as SortValue;
  const hasFilters =
    !!searchQuery ||
    selectedCategory !== "all" ||
    !!selectedLevel ||
    !!selectedStatus;

  // Keep filter state in the URL so a filtered view can be linked and survives reload.
  const setParam = (key: string, value: string, fallback = "") => {
    const next = new URLSearchParams(params);
    if (!value || value === fallback) next.delete(key);
    else next.set(key, value);
    setParams(next, { replace: true });
  };

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { all: MODULES.length };
    for (const mod of MODULES) {
      const cat = MODULE_CATEGORIES[mod.id]?.category ?? "uncategorized";
      counts[cat] = (counts[cat] ?? 0) + 1;
    }
    return counts;
  }, []);

  const filteredModules = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    const list = MODULES.filter((mod) => {
      if (
        selectedCategory !== "all" &&
        MODULE_CATEGORIES[mod.id]?.category !== selectedCategory
      ) {
        return false;
      }
      if (selectedLevel && mod.difficulty !== selectedLevel) return false;
      if (
        selectedStatus &&
        getModuleStatus(mod, completedModules, completedLessons) !==
          selectedStatus
      ) {
        return false;
      }
      if (!query) return true;
      return (
        mod.title.toLowerCase().includes(query) ||
        mod.description.toLowerCase().includes(query) ||
        mod.difficulty.toLowerCase().includes(query) ||
        MODULE_CATEGORIES[mod.id]?.label.toLowerCase().includes(query)
      );
    });
    if (sort === "shortest") {
      return [...list].sort(
        (a, b) => estimateModuleMinutes(a) - estimateModuleMinutes(b),
      );
    }
    if (sort === "xp") return [...list].sort((a, b) => b.xpReward - a.xpReward);
    return list;
  }, [
    searchQuery,
    selectedCategory,
    selectedLevel,
    selectedStatus,
    sort,
    completedModules,
    completedLessons,
  ]);

  const doneCount = completedModules.length;

  const assignRandom = () => {
    const pool = MODULES.filter(
      (m) => !completedModules.includes(m.id) && !m.locked,
    );
    const pick = pool[Math.floor(Math.random() * pool.length)];
    if (pick) navigate(`/modules/${pick.id}`);
  };

  return (
    <div className="space-y-10">
      <header className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end">
        <div>
          <p className="flex items-center gap-2 range-readout mb-4">
            <span className="range-dot" aria-hidden="true" />
            Mission board · {MODULES.length} ops · {doneCount} cleared
          </p>
          <h1 className="text-h1">Active Operations</h1>
          <p className="mt-3 text-muted-foreground max-w-[60ch]">
            Every module mixes short briefings, knowledge checks and hands-on
            code labs. Times are estimates from lesson length.
          </p>
        </div>
        <button
          type="button"
          onClick={assignRandom}
          className="btn-ghost-rule self-start lg:self-end"
        >
          <Dices className="w-4 h-4" aria-hidden="true" />
          Assign me a random mission
        </button>
      </header>

      <div className="space-y-4 border-y border-border py-5">
        <div className="relative">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            type="search"
            value={searchQuery}
            onChange={(e) => setParam("q", e.target.value)}
            placeholder="Search by name, topic, or difficulty"
            className="pl-9"
            aria-label="Search modules"
          />
        </div>

        <div
          role="group"
          aria-label="Category"
          className="flex gap-2 overflow-x-auto pb-1 -mb-1"
        >
          {CATEGORY_OPTIONS.map((option) => (
            <button
              key={option.value}
              type="button"
              aria-pressed={selectedCategory === option.value}
              onClick={() => setParam("cat", option.value, "all")}
              className="filter-pill shrink-0"
            >
              {option.label}
              <span className="tabular-nums opacity-60">
                {categoryCounts[option.value] ?? 0}
              </span>
            </button>
          ))}
        </div>

        <button
          type="button"
          className="md:hidden filter-pill"
          aria-expanded={showRefine}
          aria-controls="refine-filters"
          onClick={() => setShowRefine((v) => !v)}
        >
          <SlidersHorizontal className="w-3.5 h-3.5" aria-hidden="true" />
          Refine
          {(selectedLevel || selectedStatus || sort !== "catalog") && (
            <span
              className="h-1.5 w-1.5 rounded-full bg-primary"
              aria-label="(active)"
            />
          )}
        </button>
        <div
          id="refine-filters"
          className={clsx(
            "flex-wrap items-center gap-x-6 gap-y-3 md:flex",
            showRefine ? "flex" : "hidden",
          )}
        >
          <div
            role="group"
            aria-label="Difficulty"
            className="flex flex-wrap items-center gap-2"
          >
            <span className="ui-label mr-1">Level</span>
            {LEVEL_OPTIONS.map((level) => (
              <button
                key={level}
                type="button"
                aria-pressed={selectedLevel === level}
                onClick={() =>
                  setParam("level", selectedLevel === level ? "" : level)
                }
                className="filter-pill filter-pill-soft !h-8"
              >
                {level}
              </button>
            ))}
          </div>
          <div
            role="group"
            aria-label="Status"
            className="flex flex-wrap items-center gap-2"
          >
            <span className="ui-label mr-1">Status</span>
            {STATUS_OPTIONS.map((status) => (
              <button
                key={status.value}
                type="button"
                aria-pressed={selectedStatus === status.value}
                onClick={() =>
                  setParam(
                    "status",
                    selectedStatus === status.value ? "" : status.value,
                  )
                }
                className="filter-pill filter-pill-soft !h-8"
              >
                {status.label}
              </button>
            ))}
          </div>
          <label className="flex items-center gap-2 lg:ml-auto">
            <span className="ui-label">Sort</span>
            <select
              value={sort}
              onChange={(e) => setParam("sort", e.target.value, "catalog")}
              className="ui-input !h-9 pr-8 text-body-sm"
            >
              {SORT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div
          className="flex items-center justify-between gap-4 font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground"
          aria-live="polite"
        >
          <span>
            Showing {filteredModules.length} of {MODULES.length}
          </span>
          {hasFilters && (
            <button
              type="button"
              onClick={() =>
                setParams(
                  new URLSearchParams(sort === "catalog" ? "" : `sort=${sort}`),
                  { replace: true },
                )
              }
              className="inline-flex items-center gap-1 hover:text-foreground"
            >
              <X className="w-3 h-3" aria-hidden="true" />
              Clear filters
            </button>
          )}
        </div>
      </div>

      {filteredModules.length === 0 ? (
        <EmptyState
          title="No missions match"
          description="Try a different search term or clear the filters."
          icon={<Search className="w-7 h-7" />}
          action={
            <Button
              type="button"
              variant="secondary"
              onClick={() =>
                setParams(new URLSearchParams(), { replace: true })
              }
            >
              Clear filters
            </Button>
          }
        />
      ) : (
        <ol aria-label="Modules">
          {filteredModules.map((module) => {
            const status = getModuleStatus(
              module,
              completedModules,
              completedLessons,
            );
            const isCompleted = status === "done";
            const isLocked = module.locked;
            const lessonDone = module.lessons.filter((l) =>
              completedLessons.includes(l.id),
            ).length;
            const lessonTotal = module.lessons.length;
            const mix = getLessonMix(module);
            const covers = module.lessons
              .filter((l) => l.type === "theory")
              .slice(0, 3)
              .map((l) => l.title);
            const action = isCompleted
              ? "Review"
              : lessonDone > 0
                ? "Continue"
                : "Start Mission";

            return (
              <li
                key={module.id}
                className={clsx(
                  "group relative grid gap-4 border-b border-border py-6 md:grid-cols-[64px_minmax(0,1fr)_200px] md:gap-6",
                  isLocked && "opacity-60",
                )}
              >
                <span
                  className={clsx(
                    "absolute left-0 top-0 h-full w-[3px] -ml-4 md:-ml-6 transition-colors",
                    isLocked ? "" : "group-hover:bg-primary",
                  )}
                  aria-hidden="true"
                />
                <div className="flex md:flex-col md:items-start items-center gap-3">
                  <span className="font-display font-extrabold [font-stretch:75%] text-h2 leading-none tabular-nums text-muted-foreground group-hover:text-foreground transition-colors">
                    {opNumber(module.id)}
                  </span>
                  {isCompleted && (
                    <span className="inline-grid h-6 w-6 place-items-center rounded-[var(--radius-xs)] bg-signal text-signal-ink">
                      <Check className="w-3.5 h-3.5" aria-hidden="true" />
                      <span className="sr-only">Completed</span>
                    </span>
                  )}
                </div>

                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <span
                      className={clsx("ui-chip", LEVEL_TONE[module.difficulty])}
                    >
                      {module.difficulty}
                    </span>
                    {MODULE_CATEGORIES[module.id] && (
                      <span className="ui-chip">
                        {MODULE_CATEGORIES[module.id].label}
                      </span>
                    )}
                  </div>
                  <h2 className="text-h3">
                    {isLocked ? (
                      module.title
                    ) : (
                      <Link
                        to={`/modules/${module.id}`}
                        className="after:absolute after:inset-0 after:content-[''] focus-visible:outline-none"
                      >
                        {module.title}
                      </Link>
                    )}
                  </h2>
                  <p className="mt-1.5 text-body-sm text-muted-foreground max-w-[64ch]">
                    {module.description}
                  </p>
                  {covers.length > 0 && (
                    <p className="mt-3 text-[13px] text-muted-foreground">
                      <span className="ui-label !text-[10px] mr-2">Covers</span>
                      {covers.join(" · ")}
                    </p>
                  )}
                </div>

                <div className="flex flex-col gap-3 md:items-end md:text-right">
                  <dl className="flex flex-wrap md:flex-col md:items-end gap-x-4 gap-y-1 font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground tabular-nums">
                    <div className="flex md:justify-end gap-1.5">
                      <dt className="sr-only">Estimated time</dt>
                      <dd className="text-foreground">
                        {formatMinutes(estimateModuleMinutes(module))}
                      </dd>
                    </div>
                    <div className="flex md:justify-end gap-1.5">
                      <dt className="sr-only">Lessons</dt>
                      <dd>
                        {[
                          mix.theory &&
                            `${mix.theory} brief${mix.theory > 1 ? "s" : ""}`,
                          mix.quiz &&
                            `${mix.quiz} quiz${mix.quiz > 1 ? "zes" : ""}`,
                          mix.lab && `${mix.lab} lab${mix.lab > 1 ? "s" : ""}`,
                        ]
                          .filter(Boolean)
                          .join(" · ")}
                      </dd>
                    </div>
                    <div className="flex md:justify-end gap-1.5">
                      <dt className="sr-only">Reward</dt>
                      <dd>{module.xpReward} XP</dd>
                    </div>
                  </dl>
                  <div className="w-full md:w-40">
                    <Progress
                      value={lessonDone}
                      max={lessonTotal || 1}
                      aria-label={`${lessonDone} of ${lessonTotal} lessons complete`}
                    />
                    <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground tabular-nums">
                      {lessonDone}/{lessonTotal} lessons
                    </p>
                  </div>
                  {isLocked ? (
                    <span className="inline-flex items-center gap-1.5 font-mono text-caption uppercase tracking-[0.12em] text-muted-foreground">
                      <Lock className="w-3.5 h-3.5" aria-hidden="true" /> Locked
                    </span>
                  ) : (
                    <span
                      className={clsx(
                        "relative z-10 inline-flex items-center gap-1.5 font-mono text-caption uppercase tracking-[0.12em]",
                        isCompleted
                          ? "text-muted-foreground"
                          : "text-foreground",
                      )}
                      aria-hidden="true"
                    >
                      {action}
                      <ArrowRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5" />
                    </span>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
};

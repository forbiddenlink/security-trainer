import React, { useState, useMemo } from "react";
import { MODULES } from "../data/modules";
import { Link } from "react-router-dom";
import { Shield, Lock, CheckCircle } from "lucide-react";
import { useGameStore } from "../store/gameStore";
import { Button, Card } from "../components/ui";
import { clsx } from "clsx";

const MODULE_CATEGORIES: Record<string, { label: string; category: string }> = {
  // Web Security
  'owasp-intro': { label: 'Web Security', category: 'web-security' },
  'sql-injection': { label: 'Web Security', category: 'web-security' },
  'xss-basics': { label: 'Web Security', category: 'web-security' },
  'csrf-attacks': { label: 'Web Security', category: 'web-security' },
  'clickjacking': { label: 'Web Security', category: 'web-security' },
  'idor-basics': { label: 'Web Security', category: 'web-security' },
  'sensitive-data-exposure': { label: 'Web Security', category: 'web-security' },
  'cors-misconfig': { label: 'Web Security', category: 'web-security' },
  'file-upload': { label: 'Web Security', category: 'web-security' },
  'security-misconfig': { label: 'Web Security', category: 'web-security' },
  'path-traversal': { label: 'Web Security', category: 'web-security' },
  'session-management': { label: 'Web Security', category: 'web-security' },

  // API & Backend
  'api-security': { label: 'API & Backend', category: 'api-backend' },
  'jwt-vulnerabilities': { label: 'API & Backend', category: 'api-backend' },
  'graphql-security': { label: 'API & Backend', category: 'api-backend' },
  'broken-auth': { label: 'API & Backend', category: 'api-backend' },
  'command-injection': { label: 'API & Backend', category: 'api-backend' },
  'ssrf-attacks': { label: 'API & Backend', category: 'api-backend' },
  'xxe-attacks': { label: 'API & Backend', category: 'api-backend' },
  'insecure-deserialization': { label: 'API & Backend', category: 'api-backend' },
  'oauth-security': { label: 'API & Backend', category: 'api-backend' },

  // Advanced
  'business-logic': { label: 'Advanced', category: 'advanced' },
  'race-conditions': { label: 'Advanced', category: 'advanced' },
  'prototype-pollution': { label: 'Advanced', category: 'advanced' },
  'subdomain-takeover': { label: 'Advanced', category: 'advanced' },
  'websocket-security': { label: 'Advanced', category: 'advanced' },
  'vulnerable-components': { label: 'Advanced', category: 'advanced' },
  'logging-monitoring': { label: 'Advanced', category: 'advanced' },
  'ai-security': { label: 'Advanced', category: 'advanced' },
  'social-engineering': { label: 'Advanced', category: 'advanced' },

  // Infrastructure
  'container-security': { label: 'Infrastructure', category: 'infrastructure' },
  'supply-chain-security': { label: 'Infrastructure', category: 'infrastructure' },
  'cloud-security': { label: 'Infrastructure', category: 'infrastructure' },
  'incident-response': { label: 'Infrastructure', category: 'infrastructure' },

  // Awareness
  'phishing-awareness': { label: 'Awareness', category: 'awareness' },
  'password-data-hygiene': { label: 'Awareness', category: 'awareness' },
  'incident-reporting': { label: 'Awareness', category: 'awareness' },
  'safe-browsing-remote': { label: 'Awareness', category: 'awareness' },

  // Compliance
  'gdpr-fundamentals': { label: 'Compliance', category: 'compliance' },
  'pci-dss-essentials': { label: 'Compliance', category: 'compliance' },
  'soc2-awareness': { label: 'Compliance', category: 'compliance' },
  'hipaa-basics': { label: 'Compliance', category: 'compliance' },
};

const FILTER_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'web-security', label: 'Web Security' },
  { value: 'api-backend', label: 'API & Backend' },
  { value: 'advanced', label: 'Advanced' },
  { value: 'infrastructure', label: 'Infrastructure' },
  { value: 'awareness', label: 'Awareness' },
  { value: 'compliance', label: 'Compliance' },
] as const;

export const Modules: React.FC = () => {
  const { completedModules } = useGameStore();
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { all: MODULES.length };
    for (const mod of MODULES) {
      const cat = MODULE_CATEGORIES[mod.id]?.category ?? 'uncategorized';
      counts[cat] = (counts[cat] ?? 0) + 1;
    }
    return counts;
  }, []);

  const filteredModules = useMemo(() => {
    if (selectedCategory === 'all') return MODULES;
    return MODULES.filter(
      (mod) => MODULE_CATEGORIES[mod.id]?.category === selectedCategory,
    );
  }, [selectedCategory]);

  return (
    <div className="space-y-8 max-w-5xl mx-auto animate-in fade-in duration-500">
      <div className="flex flex-col gap-2">
        <h1 className="text-h1">Active Operations</h1>
        <p className="text-muted-foreground text-body">
          Select a mission to upgrade your security clearance level.
        </p>
      </div>

      <div className="flex gap-2 overflow-x-auto pb-1 -mb-1 scrollbar-none">
        {FILTER_OPTIONS.map((option) => (
          <button
            key={option.value}
            type="button"
            onClick={() => setSelectedCategory(option.value)}
            className={clsx(
              "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-3 py-1.5 text-sm font-medium transition-colors shrink-0",
              selectedCategory === option.value
                ? "bg-primary text-primary-foreground"
                : "bg-muted/40 text-muted-foreground hover:bg-muted/60",
            )}
          >
            {option.label}
            <span
              className={clsx(
                "inline-flex items-center justify-center rounded-full px-1.5 min-w-[1.25rem] text-xs font-semibold",
                selectedCategory === option.value
                  ? "bg-primary-foreground/20 text-primary-foreground"
                  : "bg-muted/60 text-muted-foreground",
              )}
            >
              {categoryCounts[option.value] ?? 0}
            </span>
          </button>
        ))}
      </div>

      <div className="grid gap-6">
        {filteredModules.map((module) => {
          const isCompleted = completedModules.includes(module.id);
          const isLocked = module.locked; // Logic could be expanded based on level

          return (
            <Card
              key={module.id}
              className={clsx(
                "group relative overflow-hidden ui-card-md",
                isLocked ? "bg-muted/20 opacity-70" : "ui-card-interactive",
              )}
            >
              {!isLocked && (
                <div className="absolute inset-0 bg-linear-to-r from-primary/6 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none" />
              )}

              <div className="grid gap-6 md:grid-cols-[1fr_220px] items-start md:items-center relative z-10">
                <div className="flex gap-4 min-w-0">
                  <div
                    className={clsx(
                      "h-12 w-12 shrink-0 grid place-items-center rounded-[var(--radius-sm)] relative overflow-hidden",
                      isCompleted
                        ? "bg-accent/12 text-accent"
                        : "bg-primary/12 text-primary",
                    )}
                  >
                    <div className="absolute inset-0 bg-current opacity-0 group-hover:opacity-10 transition-opacity" />
                    <Shield className="w-6 h-6 relative z-10" />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-3 mb-1 flex-wrap">
                      <h3 className="text-h4 group-hover:text-primary transition-colors">
                        {module.title}
                      </h3>
                      {isCompleted && (
                        <span className="ui-chip text-accent border-accent/30 bg-accent/10">
                          <CheckCircle className="w-3 h-3" /> Completed
                        </span>
                      )}
                      <span
                        className={clsx(
                          "ui-chip font-mono",
                          module.difficulty === "Beginner"
                            ? "border-accent/35 text-accent bg-accent/8"
                            : module.difficulty === "Intermediate"
                              ? "border-warning/35 text-warning bg-warning/8"
                              : "border-destructive/35 text-destructive bg-destructive/8",
                        )}
                      >
                        {module.difficulty}
                      </span>
                    </div>
                    <p className="text-muted-foreground max-w-xl group-hover:text-foreground/85 transition-colors">
                      {module.description}
                    </p>
                  </div>
                </div>

                <div className="flex items-center justify-between md:justify-end gap-5">
                  <div className="text-left md:text-right">
                    <p className="ui-label">Reward</p>
                    <p className="text-mono text-primary font-semibold">
                      {module.xpReward} XP
                    </p>
                  </div>

                  {isLocked ? (
                    <Button
                      disabled
                      variant="secondary"
                      className="gap-2 border-transparent bg-muted text-muted-foreground"
                    >
                      <Lock className="w-4 h-4" /> Locked
                    </Button>
                  ) : (
                    <Link
                      to={`/modules/${module.id}`}
                      className={clsx(
                        "inline-flex h-10 items-center justify-center gap-2 rounded-[var(--radius-sm)] px-5 font-semibold transition-colors relative overflow-hidden",
                        isCompleted
                          ? "bg-muted hover:bg-muted/80 text-foreground border border-border hover:border-primary/30"
                          : "bg-primary text-primary-foreground hover:bg-primary/90",
                      )}
                    >
                      <span className="relative z-10">
                        {isCompleted ? "Review" : "Start Mission"}
                      </span>
                    </Link>
                  )}
                </div>
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
};

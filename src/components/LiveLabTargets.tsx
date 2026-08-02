import React, { useEffect, useState } from "react";
import { ExternalLink, Server, Circle } from "lucide-react";
import {
  LIVE_TARGETS,
  getTargetsForModule,
  getTargetsForCtfTags,
  type LiveTarget,
} from "../data/liveTargets";
import { Chip } from "./ui";

interface LiveLabTargetsProps {
  moduleId?: string;
  tags?: string[];
  /** Show all targets (lab stack overview) */
  showAll?: boolean;
  className?: string;
}

/** Only meaningful on a localhost origin — over HTTPS (prod) an http://localhost
 *  probe is mixed-content blocked and would always report offline. */
const canProbe =
  typeof window !== "undefined" &&
  (window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1");

async function probeTarget(url: string): Promise<boolean> {
  try {
    await fetch(url, { mode: "no-cors", cache: "no-store" });
    // no-cors opaque response still means something answered (or browser didn't block)
    return true;
  } catch {
    return false;
  }
}

const TargetRow: React.FC<{ target: LiveTarget }> = ({ target }) => {
  const [online, setOnline] = useState<boolean | null>(null);

  useEffect(() => {
    if (!canProbe) return;
    let cancelled = false;
    const check = async () => {
      const ok = await probeTarget(target.url);
      if (!cancelled) setOnline(ok);
    };
    check();
    const id = window.setInterval(check, 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [target.url]);

  return (
    <a
      href={target.url}
      target="_blank"
      rel="noopener noreferrer"
      className="mission-card ui-card flex items-start gap-3 p-3 hover:border-primary/40 transition-colors"
    >
      <div className="ui-icon-box-sm ui-icon-box bg-primary/10 text-primary shrink-0">
        <Server className="w-4 h-4" aria-hidden="true" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-semibold text-body-sm">{target.name}</span>
          <Chip tone={online ? "accent" : "default"}>
            <Circle
              className={`w-2 h-2 ${online ? "fill-accent text-accent" : "fill-muted-foreground text-muted-foreground"}`}
              aria-hidden="true"
            />
            {!canProbe
              ? "Local"
              : online === null
                ? "Checking"
                : online
                  ? "Reachable"
                  : "Offline"}
          </Chip>
        </div>
        <p className="text-caption text-muted-foreground normal-case tracking-normal mt-1">
          {target.description}
        </p>
        <p className="text-mono text-primary mt-1.5 text-body-sm">
          {target.url}
        </p>
      </div>
      <ExternalLink
        className="w-4 h-4 text-muted-foreground shrink-0 mt-1"
        aria-hidden="true"
      />
    </a>
  );
};

export const LiveLabTargets: React.FC<LiveLabTargetsProps> = ({
  moduleId,
  tags,
  showAll = false,
  className,
}) => {
  const targets = showAll
    ? LIVE_TARGETS
    : moduleId
      ? getTargetsForModule(moduleId)
      : tags
        ? getTargetsForCtfTags(tags)
        : [];

  if (targets.length === 0) return null;

  return (
    <section className={className} aria-label="Live practice targets">
      <div className="flex items-center justify-between mb-3">
        <div>
          <p className="ui-label">Live Range</p>
          <p className="text-body-sm text-muted-foreground">
            Local security-lab containers for hands-on practice
          </p>
        </div>
      </div>
      <div className="space-y-2">
        {targets.map((t) => (
          <TargetRow key={t.id} target={t} />
        ))}
      </div>
      <p className="text-caption text-muted-foreground mt-3 normal-case tracking-normal">
        Start with <code className="text-mono">docker compose up -d</code> in{" "}
        <code className="text-mono">security-lab/</code>
      </p>
    </section>
  );
};

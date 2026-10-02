import React, { useEffect, useId, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import { Search, CornerDownLeft } from "lucide-react";
import { clsx } from "clsx";
import { MODULES } from "../data/modules";
import { LEARNING_PATHS } from "../data/learningPaths";
import { CTF_CHALLENGES } from "../data/ctfChallenges";
import {
  rankPaletteItems,
  type PaletteItem,
  type PaletteKind,
} from "../lib/paletteSearch";
import { estimateModuleMinutes, formatMinutes } from "../lib/moduleMeta";
import { useFocusTrap } from "../utils/useFocusTrap";
import { OPEN_PALETTE_EVENT as OPEN_EVENT } from "../lib/paletteEvents";

const PAGES: PaletteItem[] = [
  {
    id: "p-dash",
    kind: "page",
    title: "Dashboard",
    href: "/",
    keywords: "home mission control",
  },
  {
    id: "p-mod",
    kind: "page",
    title: "All modules",
    href: "/modules",
    keywords: "catalog operations",
  },
  {
    id: "p-paths",
    kind: "page",
    title: "Learning paths",
    href: "/paths",
    keywords: "tracks",
  },
  {
    id: "p-ctf",
    kind: "page",
    title: "CTF challenges",
    href: "/ctf",
    keywords: "flags capture",
  },
  {
    id: "p-rev",
    kind: "page",
    title: "Intel review",
    href: "/reviews",
    keywords: "spaced repetition refresh",
  },
  {
    id: "p-exam",
    kind: "page",
    title: "Final exam",
    href: "/challenge",
    keywords: "test certificate",
  },
  {
    id: "p-lead",
    kind: "page",
    title: "Leaderboard",
    href: "/leaderboard",
    keywords: "rankings",
  },
  {
    id: "p-prof",
    kind: "page",
    title: "Profile",
    href: "/profile",
    keywords: "badges certificate settings",
  },
];

const KIND_LABEL: Record<PaletteKind, string> = {
  page: "Page",
  module: "Module",
  path: "Path",
  ctf: "CTF",
};

function buildItems(): PaletteItem[] {
  const modules: PaletteItem[] = MODULES.map((m) => ({
    id: `m-${m.id}`,
    kind: "module",
    title: m.title,
    href: `/modules/${m.id}`,
    subtitle: `${m.difficulty} · ${formatMinutes(estimateModuleMinutes(m))}`,
    keywords: `${m.description} ${m.category ?? ""}`,
  }));
  const paths: PaletteItem[] = LEARNING_PATHS.map((p) => ({
    id: `l-${p.id}`,
    kind: "path",
    title: p.title,
    href: `/paths/${p.id}`,
    subtitle: `${p.modules.length} modules · ${p.difficulty}`,
    keywords: `${p.codename} ${p.description}`,
  }));
  const flags: PaletteItem[] = CTF_CHALLENGES.map((c) => ({
    id: `c-${c.id}`,
    kind: "ctf",
    title: c.title,
    href: `/ctf?challenge=${encodeURIComponent(c.id)}`,
    subtitle: `${c.points} pts${c.difficulty ? ` · ${c.difficulty}` : ""}`,
    keywords: `${c.category} ${(c.tags ?? []).join(" ")}`,
  }));
  return [...PAGES, ...modules, ...paths, ...flags];
}

export const CommandPalette: React.FC = () => {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const navigate = useNavigate();
  const close = () => setOpen(false);
  const trapRef = useFocusTrap<HTMLDivElement>(open, close);
  const listRef = useRef<HTMLUListElement>(null);
  const listId = useId();
  const allItems = useMemo(() => buildItems(), []);
  const results = useMemo(
    () => rankPaletteItems(allItems, query).slice(0, 40),
    [allItems, query],
  );

  useEffect(() => {
    const onOpen = () => {
      setQuery("");
      setActive(0);
      setOpen(true);
    };
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const typing =
        !!target &&
        (target.isContentEditable ||
          ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName) ||
          !!target.closest(".monaco-editor, .xterm"));
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => {
          if (!o) {
            setQuery("");
            setActive(0);
          }
          return !o;
        });
      } else if (e.key === "/" && !typing) {
        e.preventDefault();
        onOpen();
      }
    };
    window.addEventListener(OPEN_EVENT, onOpen);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener(OPEN_EVENT, onOpen);
      window.removeEventListener("keydown", onKey);
    };
  }, []);

  useEffect(() => {
    listRef.current
      ?.querySelector<HTMLElement>(`[data-index="${active}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const go = (item: PaletteItem | undefined) => {
    if (!item) return;
    setOpen(false);
    navigate(item.href);
  };

  const onInputKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(i + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      go(results[active]);
    }
  };

  if (typeof document === "undefined") return null;

  return createPortal(
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center p-4 pt-[12vh]">
          <motion.div
            role="presentation"
            className="absolute inset-0 bg-background/75 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={close}
          />
          <motion.div
            ref={trapRef}
            role="dialog"
            aria-modal="true"
            aria-label="Jump to"
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.16, ease: [0.2, 0.8, 0.2, 1] }}
            className="relative z-10 w-full max-w-xl border border-border bg-popover text-popover-foreground rounded-[var(--radius-md)] shadow-[var(--shadow-lg)] overflow-hidden"
          >
            <div className="flex items-center gap-3 px-4 h-14 border-b border-border">
              <Search
                className="w-4 h-4 text-muted-foreground shrink-0"
                aria-hidden="true"
              />
              <input
                autoFocus
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setActive(0);
                }}
                onKeyDown={onInputKey}
                placeholder="Search modules, paths, flags, pages"
                className="flex-1 bg-transparent outline-none text-body placeholder:text-muted-foreground"
                role="combobox"
                aria-expanded="true"
                aria-controls={listId}
                aria-activedescendant={
                  results[active] ? `${listId}-${active}` : undefined
                }
                aria-autocomplete="list"
                aria-label="Search"
              />
              <kbd className="kbd">Esc</kbd>
            </div>
            <ul
              ref={listRef}
              id={listId}
              role="listbox"
              aria-label="Results"
              className="max-h-[50vh] overflow-y-auto py-1.5"
            >
              {results.length === 0 && (
                <li className="px-4 py-8 text-center text-body-sm text-muted-foreground">
                  No match for “{query}”. Try a topic like “jwt” or “xss”.
                </li>
              )}
              {results.map((item, i) => (
                <li
                  key={item.id}
                  id={`${listId}-${i}`}
                  data-index={i}
                  role="option"
                  aria-selected={i === active}
                  onMouseMove={() => setActive(i)}
                  onClick={() => go(item)}
                  className={clsx(
                    "mx-1.5 flex items-center gap-3 rounded-[var(--radius-sm)] px-3 py-2.5 cursor-pointer",
                    i === active ? "bg-muted" : "",
                  )}
                >
                  <span className="w-14 shrink-0 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
                    {KIND_LABEL[item.kind]}
                  </span>
                  <span className="flex-1 min-w-0">
                    <span className="block truncate text-body-sm font-medium">
                      {item.title}
                    </span>
                    {item.subtitle && (
                      <span className="block truncate font-mono text-[11px] text-muted-foreground">
                        {item.subtitle}
                      </span>
                    )}
                  </span>
                  {i === active && (
                    <CornerDownLeft
                      className="w-3.5 h-3.5 text-muted-foreground"
                      aria-hidden="true"
                    />
                  )}
                </li>
              ))}
            </ul>
            <div className="flex items-center gap-4 border-t border-border px-4 h-10 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
              <span>
                <kbd className="kbd">↑↓</kbd> Move
              </span>
              <span>
                <kbd className="kbd">Enter</kbd> Open
              </span>
              <span className="ml-auto tabular-nums">
                {results.length} results
              </span>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>,
    document.body,
  );
};

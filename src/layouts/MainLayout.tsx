import React, { useState, useCallback, useEffect } from "react";
import { Outlet, useLocation, Link } from "react-router-dom";
import { Sidebar } from "../components/Sidebar";
import { Header } from "../components/Header";
import { LevelUpToast } from "../components/LevelUpToast";
import { AchievementToast } from "../components/AchievementToast";
import { CommandPalette } from "../components/CommandPalette";
import { RangeMark } from "../components/RangeMark";

const BASE_TITLE = "SecTrainer";
// Map the first path segment to a descriptive document title.
const ROUTE_TITLES: Record<string, string> = {
  "": "Mission Control",
  modules: "Modules",
  profile: "Profile",
  challenge: "Daily Challenge",
  leaderboard: "Leaderboard",
  paths: "Learning Paths",
  reviews: "Reviews",
  ctf: "CTF Challenges",
  privacy: "Privacy & Terms",
};

export const MainLayout: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const toggleSidebar = useCallback(() => setSidebarOpen((prev) => !prev), []);
  const closeSidebar = useCallback(() => setSidebarOpen(false), []);
  const { pathname } = useLocation();

  useEffect(() => {
    const seg = pathname.split("/")[1] ?? "";
    const label = ROUTE_TITLES[seg];
    document.title = label
      ? `${label} · ${BASE_TITLE}`
      : `${BASE_TITLE} | Cyber Security Training`;
  }, [pathname]);

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <a href="#main-content" className="skip-link">
        Skip to content
      </a>
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-background/70 backdrop-blur-sm z-30 lg:hidden"
          onClick={closeSidebar}
          aria-hidden="true"
        />
      )}

      {/* Sidebar - hidden on mobile by default, shown when sidebarOpen */}
      <div
        className={`fixed inset-y-0 left-0 z-40 transform transition-transform duration-300 ease-in-out lg:relative lg:translate-x-0 ${
          sidebarOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <Sidebar onNavigate={closeSidebar} />
      </div>

      <div className="flex-1 min-w-0 flex flex-col relative">
        <Header onMenuClick={toggleSidebar} />
        <main
          id="main-content"
          tabIndex={-1}
          className="flex-1 relative z-0 outline-none"
        >
          <div className="mx-auto w-full max-w-[1240px] px-4 py-6 md:px-8 md:py-10">
            <Outlet />
          </div>
          <footer className="mx-auto w-full max-w-[1240px] px-4 md:px-8 pb-8 pt-6 mt-8">
            <div className="border-t border-border pt-6 grid gap-6 md:grid-cols-[1fr_auto] items-start">
              <div className="flex items-start gap-3">
                <RangeMark className="w-6 h-6 text-foreground shrink-0" />
                <div>
                  <p className="font-display font-extrabold [font-stretch:75%] text-h4 leading-none">
                    SecTrainer
                  </p>
                  <p className="mt-1.5 text-body-sm text-muted-foreground max-w-md">
                    Free, hands-on application security training. Progress saves
                    in this browser; sign in only if you want to sync.
                  </p>
                </div>
              </div>
              <nav
                aria-label="Footer"
                className="flex flex-wrap gap-x-6 gap-y-2 font-mono text-caption uppercase tracking-[0.12em]"
              >
                <Link
                  to="/modules"
                  className="text-muted-foreground hover:text-foreground"
                >
                  Modules
                </Link>
                <Link
                  to="/paths"
                  className="text-muted-foreground hover:text-foreground"
                >
                  Paths
                </Link>
                <Link
                  to="/privacy"
                  className="text-muted-foreground hover:text-foreground"
                >
                  Privacy &amp; Terms
                </Link>
                <a
                  href="https://github.com/forbiddenlink/security-trainer"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-muted-foreground hover:text-foreground"
                >
                  GitHub<span className="sr-only"> (opens in a new tab)</span>
                </a>
              </nav>
            </div>
          </footer>
        </main>
        <CommandPalette />
        <LevelUpToast />
        <AchievementToast />
      </div>
    </div>
  );
};

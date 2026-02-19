import React, { useState, useCallback } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "../components/Sidebar";
import { Header } from "../components/Header";
import { LevelUpToast } from "../components/LevelUpToast";
import { AchievementToast } from "../components/AchievementToast";

export const MainLayout: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const toggleSidebar = useCallback(() => setSidebarOpen((prev) => !prev), []);
  const closeSidebar = useCallback(() => setSidebarOpen(false), []);

  return (
    <div className="flex min-h-screen bg-background text-foreground antialiased selection:bg-primary/20">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-30 lg:hidden"
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

      <div className="flex-1 flex flex-col relative overflow-hidden lg:ml-0">
        <div
          className="absolute inset-0 pointer-events-none opacity-60"
          aria-hidden="true"
        >
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(56,189,248,0.12),transparent_45%)]" />
          <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(128,145,170,0.08)_1px,transparent_1px),linear-gradient(to_bottom,rgba(128,145,170,0.08)_1px,transparent_1px)] bg-[size:26px_26px]" />
        </div>
        <Header onMenuClick={toggleSidebar} />
        <main className="flex-1 overflow-auto relative z-0">
          <div className="mx-auto w-full max-w-[1200px] px-4 py-4 md:px-6 md:py-6">
            <Outlet />
          </div>
        </main>
        <LevelUpToast />
        <AchievementToast />
      </div>
    </div>
  );
};

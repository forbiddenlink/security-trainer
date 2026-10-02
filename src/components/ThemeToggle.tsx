import React from "react";
import { Sun, Moon, Monitor } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { useThemeStore } from "../store/themeStore";

export const ThemeToggle: React.FC = () => {
  const { theme, setTheme } = useThemeStore();

  const cycleTheme = () => {
    const themes: Array<"light" | "dark" | "system"> = [
      "light",
      "dark",
      "system",
    ];
    const currentIndex = themes.indexOf(theme);
    const nextIndex = (currentIndex + 1) % themes.length;
    setTheme(themes[nextIndex]);
  };

  const getIcon = () => {
    switch (theme) {
      case "light":
        return <Sun className="w-4 h-4" />;
      case "dark":
        return <Moon className="w-4 h-4" />;
      case "system":
        return <Monitor className="w-4 h-4" />;
    }
  };

  const getLabel = () => {
    switch (theme) {
      case "light":
        return "Light mode. Click to switch to dark mode.";
      case "dark":
        return "Dark mode. Click to switch to system preference.";
      case "system":
        return "System preference. Click to switch to light mode.";
    }
  };

  return (
    <button
      type="button"
      onClick={cycleTheme}
      className="relative grid h-10 w-10 place-items-center rounded-[var(--radius-sm)] border border-border transition-colors text-muted-foreground hover:text-foreground hover:border-foreground"
      aria-label={getLabel()}
      title={`Theme: ${theme}`}
    >
      <AnimatePresence mode="wait">
        <motion.div
          key={theme}
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -4 }}
          transition={{ duration: 0.14 }}
        >
          {getIcon()}
        </motion.div>
      </AnimatePresence>
    </button>
  );
};

import { useEffect, lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { MainLayout } from "./layouts/MainLayout";
import { useThemeStore } from "./store/themeStore";
import { ErrorBoundary } from "./components/ErrorBoundary";

// Lazy load pages for code splitting
const Dashboard = lazy(() =>
  import("./pages/Dashboard").then((m) => ({ default: m.Dashboard })),
);
const Modules = lazy(() =>
  import("./pages/Modules").then((m) => ({ default: m.Modules })),
);
const LessonView = lazy(() =>
  import("./pages/LessonView").then((m) => ({ default: m.LessonView })),
);
const Profile = lazy(() =>
  import("./pages/Profile").then((m) => ({ default: m.Profile })),
);
const Challenge = lazy(() =>
  import("./pages/Challenge").then((m) => ({ default: m.Challenge })),
);
const Leaderboard = lazy(() =>
  import("./pages/Leaderboard").then((m) => ({ default: m.Leaderboard })),
);
const Paths = lazy(() =>
  import("./pages/Paths").then((m) => ({ default: m.Paths })),
);
const PathDetail = lazy(() =>
  import("./pages/PathDetail").then((m) => ({ default: m.PathDetail })),
);
const Reviews = lazy(() =>
  import("./pages/Reviews").then((m) => ({ default: m.Reviews })),
);
const AuthModal = lazy(() =>
  import("./components/AuthModal").then((m) => ({ default: m.AuthModal })),
);

// Simple loading fallback
const PageLoader = () => (
  <div className="flex items-center justify-center h-64">
    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
  </div>
);

function App() {
  const { initializeTheme } = useThemeStore();

  useEffect(() => {
    // Prevent flash of wrong theme on initial load
    document.documentElement.classList.add("no-transitions");
    initializeTheme();
    // Re-enable transitions after theme is applied
    requestAnimationFrame(() => {
      document.documentElement.classList.remove("no-transitions");
    });
  }, [initializeTheme]);

  return (
    <BrowserRouter>
      <ErrorBoundary>
        <Suspense fallback={<PageLoader />}>
          <Routes>
            <Route element={<MainLayout />}>
              <Route path="/" element={<Dashboard />} />
              <Route path="/modules" element={<Modules />} />
              <Route path="/modules/:moduleId" element={<LessonView />} />
              <Route
                path="/modules/:moduleId/:lessonId"
                element={<LessonView />}
              />
              <Route path="/profile" element={<Profile />} />
              <Route path="/challenge" element={<Challenge />} />
              <Route path="/leaderboard" element={<Leaderboard />} />
              <Route path="/paths" element={<Paths />} />
              <Route path="/paths/:pathId" element={<PathDetail />} />
              <Route path="/reviews" element={<Reviews />} />
              {/* Fallback route */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </Suspense>
      </ErrorBoundary>
      <Suspense fallback={null}>
        <AuthModal />
      </Suspense>
    </BrowserRouter>
  );
}

export default App;

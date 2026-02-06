import { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { MainLayout } from './layouts/MainLayout';
import { Dashboard } from './pages/Dashboard';
import { Modules } from './pages/Modules';
import { LessonView } from './pages/LessonView';
import { Profile } from './pages/Profile';
import { Challenge } from './pages/Challenge';
import { useThemeStore } from './store/themeStore';

function App() {
  const { initializeTheme } = useThemeStore();

  useEffect(() => {
    // Prevent flash of wrong theme on initial load
    document.documentElement.classList.add('no-transitions');
    initializeTheme();
    // Re-enable transitions after theme is applied
    requestAnimationFrame(() => {
      document.documentElement.classList.remove('no-transitions');
    });
  }, [initializeTheme]);

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<MainLayout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/modules" element={<Modules />} />
          <Route path="/modules/:moduleId" element={<LessonView />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/challenge" element={<Challenge />} />
          {/* Fallback route */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;

import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from '../components/Sidebar';
import { Header } from '../components/Header';
import { LevelUpToast } from '../components/LevelUpToast';

export const MainLayout: React.FC = () => {
    return (
        <div className="flex min-h-screen bg-background text-foreground antialiased selection:bg-primary/30">
            <Sidebar />
            <div className="flex-1 flex flex-col relative overflow-hidden">
                <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none" />
                <Header />
                <main className="flex-1 p-6 overflow-auto z-0">
                    <Outlet />
                </main>
                <LevelUpToast />
            </div>
        </div>
    );
};

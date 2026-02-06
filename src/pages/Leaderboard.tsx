import React, { useEffect } from 'react';
import { Trophy, Medal, Crown, User } from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuthStore } from '../store/authStore';
import { isSupabaseConfigured } from '../lib/supabase';

export const Leaderboard: React.FC = () => {
    const { user, leaderboard, userRank, profile, fetchLeaderboard, openAuthModal } = useAuthStore();

    useEffect(() => {
        if (isSupabaseConfigured()) {
            fetchLeaderboard();
        }
    }, [fetchLeaderboard]);

    const getRankIcon = (rank: number) => {
        switch (rank) {
            case 1:
                return <Crown className="w-6 h-6 text-yellow-500" />;
            case 2:
                return <Medal className="w-6 h-6 text-gray-400" />;
            case 3:
                return <Medal className="w-6 h-6 text-amber-600" />;
            default:
                return <span className="w-6 h-6 flex items-center justify-center text-muted-foreground font-bold">{rank}</span>;
        }
    };

    const getRankBgClass = (rank: number, isCurrentUser: boolean) => {
        if (isCurrentUser) {
            return 'bg-primary/10 border-primary/30';
        }
        switch (rank) {
            case 1:
                return 'bg-yellow-500/10 border-yellow-500/30';
            case 2:
                return 'bg-gray-400/10 border-gray-400/30';
            case 3:
                return 'bg-amber-600/10 border-amber-600/30';
            default:
                return 'bg-card border-border';
        }
    };

    if (!isSupabaseConfigured()) {
        return (
            <div className="max-w-4xl mx-auto animate-in fade-in duration-500">
                <div className="text-center py-12">
                    <Trophy className="w-16 h-16 mx-auto text-muted-foreground mb-4" />
                    <h2 className="text-2xl font-bold mb-2">Leaderboard Unavailable</h2>
                    <p className="text-muted-foreground">
                        Configure Supabase to enable the leaderboard feature.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="max-w-4xl mx-auto animate-in fade-in duration-500" role="main">
            {/* Header */}
            <section className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-yellow-500/20 to-amber-500/20 border border-yellow-500/20 p-8 mb-8">
                <div className="relative z-10">
                    <div className="flex items-center gap-3 mb-2">
                        <Trophy className="w-8 h-8 text-yellow-500" />
                        <h1 className="text-3xl font-bold">Leaderboard</h1>
                    </div>
                    <p className="text-muted-foreground text-lg">
                        Top security agents ranked by experience points
                    </p>
                </div>
                <div className="absolute top-0 right-0 -mt-16 -mr-16 w-64 h-64 bg-yellow-500/20 blur-3xl rounded-full pointer-events-none" />
            </section>

            {/* User's Rank Card */}
            {user && profile && (
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mb-8 p-6 bg-gradient-to-r from-primary/10 to-purple-500/10 border border-primary/30 rounded-xl"
                >
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 rounded-full bg-gradient-to-br from-primary to-purple-500 flex items-center justify-center text-white font-bold text-lg">
                                {profile.display_name?.[0]?.toUpperCase() || 'A'}
                            </div>
                            <div>
                                <h3 className="font-bold text-lg">{profile.display_name || 'Agent'}</h3>
                                <p className="text-muted-foreground">Your current standing</p>
                            </div>
                        </div>
                        <div className="text-right">
                            <p className="text-3xl font-bold text-primary">#{userRank || '-'}</p>
                            <p className="text-muted-foreground">{profile.xp.toLocaleString()} XP</p>
                        </div>
                    </div>
                </motion.div>
            )}

            {/* Not logged in prompt */}
            {!user && (
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mb-8 p-6 bg-muted/50 border border-border rounded-xl text-center"
                >
                    <User className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
                    <h3 className="font-bold text-lg mb-2">Join the Leaderboard</h3>
                    <p className="text-muted-foreground mb-4">
                        Sign in to save your progress and compete with other agents.
                    </p>
                    <button
                        onClick={() => openAuthModal('login')}
                        className="px-6 py-2 bg-primary text-primary-foreground font-semibold rounded-lg hover:bg-primary/90 transition-colors"
                    >
                        Sign In
                    </button>
                </motion.div>
            )}

            {/* Leaderboard List */}
            <div className="space-y-3">
                {leaderboard.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                        <Trophy className="w-12 h-12 mx-auto mb-3 opacity-50" />
                        <p>No agents on the leaderboard yet. Be the first!</p>
                    </div>
                ) : (
                    leaderboard.map((entry, index) => {
                        const isCurrentUser = user?.id === entry.id;
                        return (
                            <motion.div
                                key={entry.id}
                                initial={{ opacity: 0, x: -20 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ delay: index * 0.05 }}
                                className={`flex items-center gap-4 p-4 rounded-xl border ${getRankBgClass(entry.rank || index + 1, isCurrentUser)} transition-colors hover:border-primary/50`}
                            >
                                {/* Rank */}
                                <div className="w-10 flex justify-center">
                                    {getRankIcon(entry.rank || index + 1)}
                                </div>

                                {/* Avatar */}
                                <div
                                    className={`w-10 h-10 rounded-full flex items-center justify-center text-white font-bold ${
                                        entry.rank === 1
                                            ? 'bg-gradient-to-br from-yellow-400 to-amber-600'
                                            : entry.rank === 2
                                                ? 'bg-gradient-to-br from-gray-300 to-gray-500'
                                                : entry.rank === 3
                                                    ? 'bg-gradient-to-br from-amber-400 to-amber-700'
                                                    : 'bg-gradient-to-br from-blue-500 to-cyan-500'
                                    }`}
                                >
                                    {entry.avatar_url ? (
                                        <img
                                            src={entry.avatar_url}
                                            alt=""
                                            className="w-full h-full rounded-full object-cover"
                                        />
                                    ) : (
                                        entry.display_name?.[0]?.toUpperCase() || 'A'
                                    )}
                                </div>

                                {/* Name */}
                                <div className="flex-1">
                                    <h3 className={`font-semibold ${isCurrentUser ? 'text-primary' : ''}`}>
                                        {entry.display_name || 'Anonymous Agent'}
                                        {isCurrentUser && <span className="ml-2 text-xs text-primary">(You)</span>}
                                    </h3>
                                    <p className="text-sm text-muted-foreground">Level {entry.level}</p>
                                </div>

                                {/* XP */}
                                <div className="text-right">
                                    <p className="font-bold text-lg">{entry.xp.toLocaleString()}</p>
                                    <p className="text-xs text-muted-foreground">XP</p>
                                </div>
                            </motion.div>
                        );
                    })
                )}
            </div>
        </div>
    );
};

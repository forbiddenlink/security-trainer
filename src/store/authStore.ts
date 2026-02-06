import { create } from 'zustand';
import type { User, AuthError } from '@supabase/supabase-js';
import { supabase, isSupabaseConfigured } from '../lib/supabase';
import type { Profile, LeaderboardEntry, ProfileInsert } from '../types/database';

interface AuthState {
    user: User | null;
    profile: Profile | null;
    loading: boolean;
    error: string | null;
    isAuthModalOpen: boolean;
    authModalMode: 'login' | 'signup';
    leaderboard: LeaderboardEntry[];
    userRank: number | null;
}

interface AuthActions {
    initialize: () => Promise<void>;
    signUp: (email: string, password: string, displayName?: string) => Promise<{ error: AuthError | null }>;
    signIn: (email: string, password: string) => Promise<{ error: AuthError | null }>;
    signInWithGoogle: () => Promise<{ error: AuthError | null }>;
    signOut: () => Promise<void>;
    updateProfile: (updates: Partial<Profile>) => Promise<void>;
    syncProgressToCloud: (progress: {
        xp: number;
        level: number;
        badges: string[];
        completedModules: string[];
        completedLessons: string[];
        streakDays: number;
        lastLoginDate: string | null;
        dailyChallengeId: string | null;
        dailyChallengeDate: string | null;
        dailyChallengeCompleted: boolean;
    }) => Promise<void>;
    loadProgressFromCloud: () => Promise<Profile | null>;
    fetchLeaderboard: () => Promise<void>;
    openAuthModal: (mode: 'login' | 'signup') => void;
    closeAuthModal: () => void;
    clearError: () => void;
}

type AuthStore = AuthState & AuthActions;

export const useAuthStore = create<AuthStore>((set, get) => ({
    user: null,
    profile: null,
    loading: true,
    error: null,
    isAuthModalOpen: false,
    authModalMode: 'login',
    leaderboard: [],
    userRank: null,

    initialize: async () => {
        if (!isSupabaseConfigured() || !supabase) {
            set({ loading: false });
            return;
        }

        try {
            // Get initial session
            const { data: { session } } = await supabase.auth.getSession();

            if (session?.user) {
                set({ user: session.user });
                await get().loadProgressFromCloud();
            }

            // Listen for auth changes
            supabase.auth.onAuthStateChange(async (event, session) => {
                set({ user: session?.user || null });

                if (event === 'SIGNED_IN' && session?.user) {
                    await get().loadProgressFromCloud();
                } else if (event === 'SIGNED_OUT') {
                    set({ profile: null, userRank: null });
                }
            });
        } catch (error) {
            console.error('Auth initialization error:', error);
        } finally {
            set({ loading: false });
        }
    },

    signUp: async (email, password, displayName) => {
        if (!supabase) return { error: { message: 'Supabase not configured' } as AuthError };

        set({ loading: true, error: null });

        const { data, error } = await supabase.auth.signUp({
            email,
            password,
            options: {
                data: {
                    display_name: displayName,
                },
            },
        });

        if (error) {
            set({ loading: false, error: error.message });
            return { error };
        }

        if (data.user) {
            // Create profile record
            const profileData: ProfileInsert = {
                id: data.user.id,
                email: data.user.email ?? null,
                display_name: displayName || email?.split('@')[0] || 'Agent',
            };
            await supabase.from('profiles').insert(profileData);
        }

        set({ loading: false });
        return { error: null };
    },

    signIn: async (email, password) => {
        if (!supabase) return { error: { message: 'Supabase not configured' } as AuthError };

        set({ loading: true, error: null });

        const { error } = await supabase.auth.signInWithPassword({
            email,
            password,
        });

        if (error) {
            set({ loading: false, error: error.message });
            return { error };
        }

        set({ loading: false });
        return { error: null };
    },

    signInWithGoogle: async () => {
        if (!supabase) return { error: { message: 'Supabase not configured' } as AuthError };

        set({ loading: true, error: null });

        const { error } = await supabase.auth.signInWithOAuth({
            provider: 'google',
            options: {
                redirectTo: window.location.origin,
            },
        });

        if (error) {
            set({ loading: false, error: error.message });
            return { error };
        }

        set({ loading: false });
        return { error: null };
    },

    signOut: async () => {
        if (!supabase) return;

        set({ loading: true });
        await supabase.auth.signOut();
        set({ user: null, profile: null, loading: false, userRank: null });
    },

    updateProfile: async (updates) => {
        const { user } = get();
        if (!supabase || !user) return;

        const updateData = {
            ...updates,
            updated_at: new Date().toISOString()
        };

        const { data, error } = await supabase
            .from('profiles')
            .update(updateData)
            .eq('id', user.id)
            .select()
            .single();

        if (error) {
            console.error('Profile update error:', error);
            return;
        }

        set({ profile: data });
    },

    syncProgressToCloud: async (progress) => {
        const { user } = get();
        if (!supabase || !user) return;

        const profileData: ProfileInsert = {
            id: user.id,
            email: user.email ?? null,
            xp: progress.xp,
            level: progress.level,
            badges: progress.badges,
            completed_modules: progress.completedModules,
            completed_lessons: progress.completedLessons,
            streak_days: progress.streakDays,
            last_login_date: progress.lastLoginDate,
            daily_challenge_id: progress.dailyChallengeId,
            daily_challenge_date: progress.dailyChallengeDate,
            daily_challenge_completed: progress.dailyChallengeCompleted,
            updated_at: new Date().toISOString(),
        };

        const { data, error } = await supabase
            .from('profiles')
            .upsert(profileData)
            .select()
            .single();

        if (error) {
            console.error('Sync to cloud error:', error);
            return;
        }

        set({ profile: data });
    },

    loadProgressFromCloud: async () => {
        const { user } = get();
        if (!supabase || !user) return null;

        const { data, error } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', user.id)
            .single();

        if (error && error.code !== 'PGRST116') {
            console.error('Load from cloud error:', error);
            return null;
        }

        if (data) {
            set({ profile: data });
            return data;
        }

        // Create new profile if doesn't exist
        const profileData: ProfileInsert = {
            id: user.id,
            email: user.email ?? null,
            display_name: user.user_metadata?.display_name || user.email?.split('@')[0] || 'Agent',
        };

        const { data: newProfile, error: insertError } = await supabase
            .from('profiles')
            .insert(profileData)
            .select()
            .single();

        if (insertError) {
            console.error('Create profile error:', insertError);
            return null;
        }

        set({ profile: newProfile });
        return newProfile;
    },

    fetchLeaderboard: async () => {
        if (!supabase) {
            set({ leaderboard: [] });
            return;
        }

        const { user } = get();

        const { data, error } = await supabase
            .from('profiles')
            .select('id, display_name, avatar_url, xp, level')
            .order('xp', { ascending: false })
            .limit(50);

        if (error) {
            console.error('Fetch leaderboard error:', error);
            return;
        }

        // Add rank to each entry
        const leaderboard: LeaderboardEntry[] = (data || []).map((entry, index) => ({
            id: entry.id,
            display_name: entry.display_name,
            avatar_url: entry.avatar_url,
            xp: entry.xp,
            level: entry.level,
            rank: index + 1,
        }));

        // Find current user's rank
        let userRank: number | null = null;
        if (user) {
            const userEntry = leaderboard.find(entry => entry.id === user.id);
            if (userEntry) {
                userRank = userEntry.rank || null;
            } else {
                // User not in top 50, fetch their rank
                const { count } = await supabase
                    .from('profiles')
                    .select('id', { count: 'exact', head: true })
                    .gt('xp', get().profile?.xp || 0);

                userRank = (count || 0) + 1;
            }
        }

        set({ leaderboard, userRank });
    },

    openAuthModal: (mode) => set({ isAuthModalOpen: true, authModalMode: mode, error: null }),
    closeAuthModal: () => set({ isAuthModalOpen: false, error: null }),
    clearError: () => set({ error: null }),
}));

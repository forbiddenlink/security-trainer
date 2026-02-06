export type Json =
    | string
    | number
    | boolean
    | null
    | { [key: string]: Json | undefined }
    | Json[]

export interface Database {
    public: {
        Tables: {
            profiles: {
                Row: {
                    id: string;
                    email: string | null;
                    display_name: string | null;
                    avatar_url: string | null;
                    xp: number;
                    level: number;
                    badges: string[];
                    completed_modules: string[];
                    completed_lessons: string[];
                    streak_days: number;
                    last_login_date: string | null;
                    daily_challenge_id: string | null;
                    daily_challenge_date: string | null;
                    daily_challenge_completed: boolean;
                    updated_at: string;
                };
                Insert: {
                    id: string;
                    email?: string | null;
                    display_name?: string | null;
                    avatar_url?: string | null;
                    xp?: number;
                    level?: number;
                    badges?: string[];
                    completed_modules?: string[];
                    completed_lessons?: string[];
                    streak_days?: number;
                    last_login_date?: string | null;
                    daily_challenge_id?: string | null;
                    daily_challenge_date?: string | null;
                    daily_challenge_completed?: boolean;
                    updated_at?: string;
                };
                Update: {
                    id?: string;
                    email?: string | null;
                    display_name?: string | null;
                    avatar_url?: string | null;
                    xp?: number;
                    level?: number;
                    badges?: string[];
                    completed_modules?: string[];
                    completed_lessons?: string[];
                    streak_days?: number;
                    last_login_date?: string | null;
                    daily_challenge_id?: string | null;
                    daily_challenge_date?: string | null;
                    daily_challenge_completed?: boolean;
                    updated_at?: string;
                };
                Relationships: [];
            };
        };
        Views: {
            [_ in never]: never;
        };
        Functions: {
            [_ in never]: never;
        };
        Enums: {
            [_ in never]: never;
        };
        CompositeTypes: {
            [_ in never]: never;
        };
    };
}

export type Profile = Database['public']['Tables']['profiles']['Row'];
export type ProfileInsert = Database['public']['Tables']['profiles']['Insert'];
export type ProfileUpdate = Database['public']['Tables']['profiles']['Update'];

export interface LeaderboardEntry {
    id: string;
    display_name: string | null;
    avatar_url: string | null;
    xp: number;
    level: number;
    rank?: number;
}

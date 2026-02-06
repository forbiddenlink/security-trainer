import { createClient, SupabaseClient } from '@supabase/supabase-js';
import type { Database } from '../types/database';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

let supabaseInstance: SupabaseClient<Database> | null = null;

if (supabaseUrl && supabaseAnonKey) {
    supabaseInstance = createClient<Database>(supabaseUrl, supabaseAnonKey);
} else {
    console.warn(
        'Supabase environment variables not set. Authentication and cloud sync will be disabled.'
    );
}

export const supabase = supabaseInstance;

export const isSupabaseConfigured = (): boolean => {
    return supabaseInstance !== null;
};

// Helper to get supabase client with type assertion for use when we know it's configured
export const getSupabase = (): SupabaseClient<Database> => {
    if (!supabaseInstance) {
        throw new Error('Supabase is not configured');
    }
    return supabaseInstance;
};

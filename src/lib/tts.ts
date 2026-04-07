// Edge TTS client for mission briefings
// Note: Edge TTS requires a server-side API for the actual synthesis
// This client handles playback and caching

type VoiceOption = 'commander' | 'intel' | 'default';

interface TTSOptions {
  voice?: VoiceOption;
  rate?: string;
  onStart?: () => void;
  onEnd?: () => void;
  onError?: (error: Error) => void;
}

// Voice mapping for spy/agent theme
const VOICE_MAP: Record<VoiceOption, string> = {
  commander: 'en-GB-RyanNeural', // Authoritative British voice
  intel: 'en-US-AriaNeural', // Clear analytical voice
  default: 'en-US-GuyNeural', // Standard narrator
};

class TTSService {
  private audio: HTMLAudioElement | null = null;
  private cache: Map<string, string> = new Map();
  private isPlaying = false;

  async speak(text: string, options: TTSOptions = {}): Promise<void> {
    const { voice = 'commander', rate = '+0%', onStart, onEnd, onError } = options;

    // Stop any current playback
    this.stop();

    try {
      const cacheKey = `${text}-${voice}-${rate}`;
      let audioUrl = this.cache.get(cacheKey);

      if (!audioUrl) {
        // For now, use browser's built-in speech synthesis as fallback
        // In production, this would call an API endpoint
        const hasServerTTS = false; // Set to true when API is available

        if (hasServerTTS) {
          const response = await fetch('/api/tts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              text,
              voice: VOICE_MAP[voice],
              rate,
            }),
          });

          if (!response.ok) {
            throw new Error('TTS API failed');
          }

          const blob = await response.blob();
          audioUrl = URL.createObjectURL(blob);
          this.cache.set(cacheKey, audioUrl);
        } else {
          // Fallback to Web Speech API
          return this.speakWithWebSpeech(text, options);
        }
      }

      this.audio = new Audio(audioUrl);
      this.isPlaying = true;

      this.audio.addEventListener('ended', () => {
        this.isPlaying = false;
        onEnd?.();
      });

      this.audio.addEventListener('error', () => {
        this.isPlaying = false;
        onError?.(new Error('Audio playback failed'));
      });

      onStart?.();
      await this.audio.play();
    } catch (error) {
      this.isPlaying = false;
      onError?.(error instanceof Error ? error : new Error('TTS failed'));
    }
  }

  private speakWithWebSpeech(text: string, options: TTSOptions): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!('speechSynthesis' in window)) {
        reject(new Error('Speech synthesis not supported'));
        return;
      }

      const utterance = new SpeechSynthesisUtterance(text);
      utterance.rate = 1.0;
      utterance.pitch = 1.0;

      // Try to find a good voice
      const voices = speechSynthesis.getVoices();
      const preferredVoice = voices.find(
        (v) => v.lang.startsWith('en') && v.name.includes('Male')
      ) || voices.find((v) => v.lang.startsWith('en'));

      if (preferredVoice) {
        utterance.voice = preferredVoice;
      }

      utterance.onstart = () => {
        this.isPlaying = true;
        options.onStart?.();
      };

      utterance.onend = () => {
        this.isPlaying = false;
        options.onEnd?.();
        resolve();
      };

      utterance.onerror = (event) => {
        this.isPlaying = false;
        const error = new Error(`Speech synthesis error: ${event.error}`);
        options.onError?.(error);
        reject(error);
      };

      speechSynthesis.speak(utterance);
    });
  }

  stop(): void {
    if (this.audio) {
      this.audio.pause();
      this.audio.currentTime = 0;
      this.audio = null;
    }
    if ('speechSynthesis' in window) {
      speechSynthesis.cancel();
    }
    this.isPlaying = false;
  }

  getIsPlaying(): boolean {
    return this.isPlaying;
  }

  clearCache(): void {
    this.cache.forEach((url) => URL.revokeObjectURL(url));
    this.cache.clear();
  }
}

export const ttsService = new TTSService();

// React hook for TTS
import { useState, useCallback, useEffect } from 'react';

export function useTTS(options: Omit<TTSOptions, 'onStart' | 'onEnd' | 'onError'> = {}) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const speak = useCallback(
    async (text: string) => {
      setIsLoading(true);
      setError(null);

      await ttsService.speak(text, {
        ...options,
        onStart: () => {
          setIsLoading(false);
          setIsPlaying(true);
        },
        onEnd: () => {
          setIsPlaying(false);
        },
        onError: (err) => {
          setIsLoading(false);
          setIsPlaying(false);
          setError(err);
        },
      });
    },
    [options]
  );

  const stop = useCallback(() => {
    ttsService.stop();
    setIsPlaying(false);
    setIsLoading(false);
  }, []);

  useEffect(() => {
    return () => {
      ttsService.stop();
    };
  }, []);

  return { speak, stop, isPlaying, isLoading, error };
}

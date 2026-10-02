import React, { memo, useState } from "react";
import { Play, ExternalLink } from "lucide-react";

interface VideoEmbedProps {
  url: string;
  title?: string;
  caption?: string;
}

/**
 * Extracts YouTube video ID from various URL formats
 */
function getYouTubeId(url: string): string | null {
  const patterns = [
    /(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/)([a-zA-Z0-9_-]{11})/,
    /^([a-zA-Z0-9_-]{11})$/, // Direct video ID
  ];

  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) return match[1];
  }
  return null;
}

/**
 * Privacy-friendly video embed with click-to-load thumbnail
 */
export const VideoEmbed: React.FC<VideoEmbedProps> = memo(
  ({ url, title = "Video", caption }) => {
    const [isLoaded, setIsLoaded] = useState(false);
    const videoId = getYouTubeId(url);

    if (!videoId) {
      return (
        <div className="my-6 p-4 border border-warning/50 rounded-[var(--radius-md)] text-sm text-warning">
          Invalid video URL: {url}
        </div>
      );
    }

    const thumbnailUrl = `https://img.youtube.com/vi/${videoId}/maxresdefault.jpg`;
    const embedUrl = `https://www.youtube-nocookie.com/embed/${videoId}?autoplay=1&rel=0`;
    const watchUrl = `https://www.youtube.com/watch?v=${videoId}`;

    return (
      <figure className="my-6" aria-label={caption || title || "Video"}>
        <div className="relative aspect-video bg-[#0c0d0b] border border-border rounded-[var(--radius-md)] overflow-hidden">
          {isLoaded ? (
            <iframe
              src={embedUrl}
              title={title}
              allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
              allowFullScreen
              className="absolute inset-0 w-full h-full"
            />
          ) : (
            <button
              type="button"
              onClick={() => setIsLoaded(true)}
              className="group absolute inset-0 w-full h-full flex items-center justify-center cursor-pointer"
              aria-label={`Play video: ${title}`}
            >
              {/* Thumbnail */}
              <img
                src={thumbnailUrl}
                alt=""
                className="absolute inset-0 w-full h-full object-cover opacity-70 group-hover:opacity-90 transition-opacity"
                loading="lazy"
              />

              {/* Play button overlay */}
              <div className="relative z-10 flex flex-col items-center gap-3">
                <div className="w-14 h-14 rounded-[var(--radius-sm)] bg-signal flex items-center justify-center transition-transform group-hover:scale-105">
                  <Play className="w-6 h-6 text-signal-ink ml-0.5" />
                </div>
                <span className="px-2.5 py-1 bg-black/75 rounded-[var(--radius-xs)] font-mono text-[11px] uppercase tracking-[0.12em] text-white">
                  Click to play
                </span>
              </div>

              {/* Privacy notice */}
              <div className="absolute bottom-2 right-2 z-10">
                <span className="text-xs text-white/70 bg-black/50 px-2 py-1 rounded">
                  YouTube (privacy mode)
                </span>
              </div>
            </button>
          )}
        </div>

        {(caption || title) && (
          <figcaption className="mt-2 flex items-center justify-between text-sm text-muted-foreground">
            <span className="italic">{caption || title}</span>
            <a
              href={watchUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-primary hover:underline"
            >
              Watch on YouTube
              <ExternalLink className="w-3 h-3" />
            </a>
          </figcaption>
        )}
      </figure>
    );
  },
);

VideoEmbed.displayName = "VideoEmbed";

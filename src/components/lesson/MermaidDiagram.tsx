import React, { useEffect, useRef, useState, memo } from "react";
import { useThemeStore } from "../../store/themeStore";

interface MermaidDiagramProps {
  chart: string;
  caption?: string;
}

/**
 * Renders a Mermaid diagram styled to the current app theme
 * Lazy loads mermaid library for better bundle splitting
 */
export const MermaidDiagram: React.FC<MermaidDiagramProps> = memo(
  ({ chart, caption }) => {
    const containerRef = useRef<HTMLDivElement>(null);
    const [svg, setSvg] = useState<string>("");
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const resolvedTheme = useThemeStore((s) => s.resolvedTheme);

    useEffect(() => {
      // No ref guard here: the container only mounts after loading finishes,
      // so waiting on it meant diagrams never rendered.
      const renderDiagram = async () => {
        try {
          setLoading(true);

          // Lazy load mermaid
          const mermaid = (await import("mermaid")).default;

          // Match the app theme: ruled line art, one signal accent.
          const dark = resolvedTheme === "dark";
          mermaid.initialize({
            startOnLoad: false,
            theme: "base",
            themeVariables: {
              primaryColor: dark ? "#161813" : "#fbfbf7",
              primaryTextColor: dark ? "#ecebe4" : "#12130f",
              primaryBorderColor: dark ? "#a3a397" : "#12130f",
              lineColor: dark ? "#a3a397" : "#55554c",
              secondaryColor: dark ? "#1d1f1a" : "#e7e6dd",
              tertiaryColor: dark ? "#121410" : "#f3f2ec",
              background: dark ? "#121410" : "#fbfbf7",
              mainBkg: dark ? "#161813" : "#fbfbf7",
              nodeBorder: dark ? "#a3a397" : "#12130f",
              clusterBkg: dark ? "#121410" : "#f3f2ec",
              titleColor: dark ? "#ecebe4" : "#12130f",
              edgeLabelBackground: dark ? "#121410" : "#f3f2ec",
              actorBorder: dark ? "#d7f75b" : "#3b4a07",
              noteBkgColor: "#d7f75b",
              noteTextColor: "#12130f",
            },
            securityLevel: "strict",
            fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
          });

          // Generate unique ID for this diagram
          const id = `mermaid-${Math.random().toString(36).substr(2, 9)}`;

          const { svg: renderedSvg } = await mermaid.render(id, chart);
          setSvg(renderedSvg);
          setError(null);
        } catch (err) {
          console.error("Mermaid rendering error:", err);
          setError("Failed to render diagram");
        } finally {
          setLoading(false);
        }
      };

      renderDiagram();
    }, [chart, resolvedTheme]);

    if (loading) {
      return (
        <div className="my-6 p-8 border border-dashed border-border rounded-[var(--radius-md)] flex items-center justify-center">
          <div className="flex items-center gap-3 text-muted-foreground">
            <div className="w-4 h-4 border-2 border-foreground border-t-transparent rounded-full animate-spin" />
            <span>Loading diagram...</span>
          </div>
        </div>
      );
    }

    if (error) {
      return (
        <div className="my-6 p-4 border border-destructive/50 rounded-[var(--radius-md)] text-sm text-destructive">
          {error}
        </div>
      );
    }

    return (
      <figure className="my-6" role="figure" aria-label={caption || "Diagram"}>
        <div
          ref={containerRef}
          className="flex justify-center p-4 bg-card border border-border rounded-[var(--radius-md)] overflow-x-auto"
          dangerouslySetInnerHTML={{ __html: svg }}
        />
        {caption && (
          <figcaption className="mt-2 font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
            {caption}
          </figcaption>
        )}
      </figure>
    );
  },
);

MermaidDiagram.displayName = "MermaidDiagram";

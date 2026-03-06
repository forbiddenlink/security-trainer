import React, { useEffect, useRef, useState, memo } from "react";

interface MermaidDiagramProps {
  chart: string;
  caption?: string;
}

/**
 * Renders a Mermaid diagram with dark theme styling
 * Lazy loads mermaid library for better bundle splitting
 */
export const MermaidDiagram: React.FC<MermaidDiagramProps> = memo(
  ({ chart, caption }) => {
    const containerRef = useRef<HTMLDivElement>(null);
    const [svg, setSvg] = useState<string>("");
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
      const renderDiagram = async () => {
        if (!containerRef.current) return;

        try {
          setLoading(true);

          // Lazy load mermaid
          const mermaid = (await import("mermaid")).default;

          // Initialize with dark theme
          mermaid.initialize({
            startOnLoad: false,
            theme: "dark",
            themeVariables: {
              primaryColor: "#3b82f6",
              primaryTextColor: "#f8fafc",
              primaryBorderColor: "#3b82f6",
              lineColor: "#64748b",
              secondaryColor: "#1e293b",
              tertiaryColor: "#0f172a",
              background: "#0f172a",
              mainBkg: "#1e293b",
              nodeBorder: "#3b82f6",
              clusterBkg: "#1e293b",
              titleColor: "#f8fafc",
              edgeLabelBackground: "#1e293b",
            },
            securityLevel: "strict",
            fontFamily: "ui-monospace, monospace",
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
    }, [chart]);

    if (loading) {
      return (
        <div className="my-6 p-8 border border-border bg-slate-900/50 rounded-lg flex items-center justify-center">
          <div className="flex items-center gap-3 text-muted-foreground">
            <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            <span>Loading diagram...</span>
          </div>
        </div>
      );
    }

    if (error) {
      return (
        <div className="my-6 p-4 border border-destructive/30 bg-destructive/10 rounded-lg text-sm text-destructive">
          {error}
        </div>
      );
    }

    return (
      <figure className="my-6" role="figure" aria-label={caption || "Diagram"}>
        <div
          ref={containerRef}
          className="flex justify-center p-4 bg-slate-900/50 border border-border rounded-lg overflow-x-auto"
          dangerouslySetInnerHTML={{ __html: svg }}
        />
        {caption && (
          <figcaption className="mt-2 text-center text-sm text-muted-foreground italic">
            {caption}
          </figcaption>
        )}
      </figure>
    );
  },
);

MermaidDiagram.displayName = "MermaidDiagram";

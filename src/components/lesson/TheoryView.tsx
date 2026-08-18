import React, { memo, useMemo } from "react";
import ReactMarkdown from "react-markdown";
import rehypeRaw from "rehype-raw";
import remarkGfm from "remark-gfm";
import type { Components } from "react-markdown";
import { MermaidDiagram } from "./MermaidDiagram";
import { VideoEmbed } from "./VideoEmbed";

interface TheoryViewProps {
  content: string;
}

/**
 * Custom code block renderer that handles mermaid diagrams
 */
const CodeBlock: Components["code"] = ({ className, children, ...props }) => {
  const match = /language-(\w+)/.exec(className || "");
  const language = match ? match[1] : "";
  const content = String(children).replace(/\n$/, "");

  // Render mermaid diagrams
  if (language === "mermaid") {
    return <MermaidDiagram chart={content} />;
  }

  // Inline code (no language specified, single line)
  if (!className) {
    return (
      <code
        className="text-primary bg-muted px-1.5 py-0.5 rounded text-sm"
        {...props}
      >
        {children}
      </code>
    );
  }

  // Regular code block with syntax highlighting class
  return (
    <code className={className} {...props}>
      {children}
    </code>
  );
};

/**
 * Custom pre block that preserves styling
 */
const PreBlock: Components["pre"] = ({ children, ...props }) => {
  return (
    <pre
      className="bg-muted border border-border rounded-lg p-4 overflow-x-auto"
      {...props}
    >
      {children}
    </pre>
  );
};

/**
 * Process content to convert video shortcodes to embeds
 * Syntax: ::video[https://youtube.com/watch?v=xxx]{title="Video Title" caption="Description"}
 */
function processVideoShortcodes(content: string): string {
  const videoPattern = /::video\[([^\]]+)\](?:\{([^}]*)\})?/g;

  return content.replace(videoPattern, (_, url, attrs) => {
    const title = attrs?.match(/title="([^"]+)"/)?.[1] || "Video";
    const caption = attrs?.match(/caption="([^"]+)"/)?.[1] || "";

    // Return a custom HTML element that we'll handle in components
    return `<video-embed url="${url}" title="${title}" caption="${caption}"></video-embed>`;
  });
}

/**
 * Renders theory/instructional content in Markdown format
 * Supports:
 * - Standard markdown (headings, lists, code blocks, links)
 * - Mermaid diagrams (```mermaid code blocks)
 * - Video embeds (::video[url]{title="..." caption="..."})
 * - GitHub Flavored Markdown (tables, strikethrough, task lists)
 */
export const TheoryView: React.FC<TheoryViewProps> = memo(({ content }) => {
  // Process video shortcodes before rendering
  const processedContent = useMemo(
    () => processVideoShortcodes(content),
    [content],
  );

  const components: Components = {
    code: CodeBlock,
    pre: PreBlock,
    // Handle custom video-embed element
    // @ts-expect-error - custom element not in standard types
    "video-embed": ({
      url,
      title,
      caption,
    }: {
      url: string;
      title: string;
      caption: string;
    }) => <VideoEmbed url={url} title={title} caption={caption} />,
  };

  return (
    <div className="max-w-3xl mx-auto">
      <div className="flex items-center gap-2 mb-6">
        <span className="range-dot" aria-hidden="true" />
        <span className="range-readout">INTEL BRIEF // CLASSIFIED READING</span>
      </div>
      <div className="prose dark:prose-invert prose-headings:text-foreground prose-p:text-foreground prose-strong:text-foreground prose-code:text-primary prose-a:text-primary prose-li:text-foreground prose-table:border-border prose-th:border-border prose-td:border-border max-w-none">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          rehypePlugins={[rehypeRaw]}
          components={components}
        >
          {processedContent}
        </ReactMarkdown>
      </div>
    </div>
  );
});

TheoryView.displayName = "TheoryView";

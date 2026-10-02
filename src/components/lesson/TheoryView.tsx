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
        className="font-mono text-[0.875em] bg-muted px-1.5 py-0.5 rounded-[var(--radius-xs)]"
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
  // Mermaid blocks render their own figure; don't wrap them in a code frame.
  if (
    React.isValidElement<{ className?: string }>(children) &&
    /language-mermaid/.test(children.props.className ?? "")
  ) {
    return <>{children}</>;
  }
  return (
    <pre
      className="bg-[#0c0d0b] text-[#ecebe4] border border-border rounded-[var(--radius-md)] p-4 overflow-x-auto font-mono text-[13px] leading-relaxed"
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
    // The lesson bar owns the page h1; markdown "# Title" becomes a section h2.
    h1: ({ children }) => <h2>{children}</h2>,
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
    <article className="max-w-[70ch]">
      <p className="ui-label mb-6">Briefing</p>
      <div className="brief-prose">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          rehypePlugins={[rehypeRaw]}
          components={components}
        >
          {processedContent}
        </ReactMarkdown>
      </div>
    </article>
  );
});

TheoryView.displayName = "TheoryView";

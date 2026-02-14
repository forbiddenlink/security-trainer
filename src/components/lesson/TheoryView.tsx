import React, { memo } from "react";
import ReactMarkdown from "react-markdown";

interface TheoryViewProps {
  content: string;
}

/**
 * Renders theory/instructional content in Markdown format
 */
export const TheoryView: React.FC<TheoryViewProps> = memo(({ content }) => {
  return (
    <div className="max-w-3xl mx-auto prose prose-invert prose-headings:text-foreground prose-p:text-foreground prose-strong:text-foreground prose-code:text-primary prose-code:bg-muted prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-pre:bg-muted prose-pre:border prose-pre:border-border prose-a:text-primary prose-li:text-foreground">
      <ReactMarkdown>{content}</ReactMarkdown>
    </div>
  );
});

TheoryView.displayName = "TheoryView";

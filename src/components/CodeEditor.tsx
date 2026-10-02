import React from "react";
import Editor, { type BeforeMount } from "@monaco-editor/react";

// Editor stays dark in both app themes: it is the "instrument screen".
const defineSignalTheme: BeforeMount = (monaco) => {
  monaco.editor.defineTheme("signal-range", {
    base: "vs-dark",
    inherit: true,
    rules: [
      { token: "comment", foreground: "8a8a7e", fontStyle: "italic" },
      { token: "string", foreground: "c9e86a" },
      { token: "keyword", foreground: "8fb8ff" },
      { token: "number", foreground: "ffb547" },
    ],
    colors: {
      "editor.background": "#0c0d0b",
      "editor.foreground": "#ecebe4",
      "editorLineNumber.foreground": "#55554c",
      "editorLineNumber.activeForeground": "#d7f75b",
      "editorCursor.foreground": "#d7f75b",
      "editor.selectionBackground": "#3b4a0799",
      "editor.lineHighlightBackground": "#161813",
      "editorIndentGuide.background1": "#1f221c",
    },
  });
};

interface CodeEditorProps {
  initialCode: string;
  onChange?: (value: string | undefined) => void;
  language?: string;
  readOnly?: boolean;
}

export const CodeEditor: React.FC<CodeEditorProps> = ({
  initialCode,
  onChange,
  language = "javascript",
  readOnly = false,
}) => {
  return (
    <div className="h-full w-full overflow-hidden bg-[#0c0d0b]">
      <Editor
        height="100%"
        defaultLanguage={language}
        defaultValue={initialCode}
        theme="signal-range"
        beforeMount={defineSignalTheme}
        onChange={onChange}
        options={{
          minimap: { enabled: false },
          fontSize: 14,
          fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
          scrollBeyondLastLine: false,
          readOnly: readOnly,
          padding: { top: 16, bottom: 16 },
        }}
      />
    </div>
  );
};

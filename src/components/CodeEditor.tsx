import React from 'react';
import Editor from '@monaco-editor/react';

interface CodeEditorProps {
    initialCode: string;
    onChange?: (value: string | undefined) => void;
    language?: string;
    readOnly?: boolean;
}

export const CodeEditor: React.FC<CodeEditorProps> = ({
    initialCode,
    onChange,
    language = 'javascript',
    readOnly = false
}) => {
    return (
        <div className="h-full w-full overflow-hidden rounded-lg border border-border bg-[#1e1e1e]">
            <Editor
                height="100%"
                defaultLanguage={language}
                defaultValue={initialCode}
                theme="vs-dark"
                onChange={onChange}
                options={{
                    minimap: { enabled: false },
                    fontSize: 14,
                    scrollBeyondLastLine: false,
                    readOnly: readOnly,
                    padding: { top: 16, bottom: 16 },
                }}
            />
        </div>
    );
};

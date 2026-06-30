import Editor, { type Monaco } from '@monaco-editor/react';
import type { editor } from 'monaco-editor';

export function CodeEditor({
  value,
  language = 'text',
  height = '420px',
  readOnly = true,
  onChange,
}: {
  value: string;
  language?: string;
  height?: string | number;
  readOnly?: boolean;
  onChange?: (value: string) => void;
}) {
  const beforeMount = (monaco: Monaco) => {
    monaco.editor.defineTheme('adversarygraph-dark', {
      base: 'vs-dark',
      inherit: true,
      rules: [],
      colors: {
        'editor.background': '#020617',
        'editorLineNumber.foreground': '#64748b',
      },
    });
  };
  const options: editor.IStandaloneEditorConstructionOptions = {
    readOnly,
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    fontSize: 12,
    fontFamily: 'JetBrains Mono, Fira Code, monospace',
    wordWrap: 'on',
    automaticLayout: true,
  };

  return (
    <Editor
      height={height}
      language={language}
      value={value}
      theme="adversarygraph-dark"
      beforeMount={beforeMount}
      options={options}
      onChange={next => onChange?.(next ?? '')}
    />
  );
}

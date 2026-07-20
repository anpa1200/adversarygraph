import Editor, { loader, type Monaco } from '@monaco-editor/react';
import * as monaco from 'monaco-editor/esm/vs/editor/editor.api.js';
import 'monaco-editor/esm/vs/basic-languages/cpp/cpp.contribution.js';
import 'monaco-editor/esm/vs/basic-languages/sql/sql.contribution.js';
import 'monaco-editor/esm/vs/language/json/monaco.contribution.js';
import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker';
import JsonWorker from 'monaco-editor/esm/vs/language/json/json.worker?worker';
import type { editor } from 'monaco-editor';

// Keep the editor inside the deployment boundary. The loader defaults to a
// public CDN, which is intentionally blocked by the production CSP and leaves
// restricted or offline installations on an indefinite loading screen.
loader.config({ monaco });

if (typeof self !== 'undefined') {
  self.MonacoEnvironment = {
    getWorker: (_moduleId: string, label: string) => (
      label === 'json' ? new JsonWorker() : new EditorWorker()
    ),
  };
}

export function CodeEditor({
  value,
  language = 'plaintext',
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
      language={language === 'asm' ? 'plaintext' : language}
      value={value}
      theme="adversarygraph-dark"
      beforeMount={beforeMount}
      options={options}
      onChange={next => onChange?.(next ?? '')}
      loading={<div role="status" className="flex h-full items-center justify-center text-xs text-gray-500">Loading secure local editor…</div>}
      wrapperProps={{ 'data-testid': 'code-editor' }}
    />
  );
}

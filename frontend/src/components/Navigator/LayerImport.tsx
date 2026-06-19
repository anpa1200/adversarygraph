/**
 * Modal panel for importing an ATT&CK Navigator JSON layer.
 *
 * Accepts the official Navigator layer format:
 *   { techniques: [{ techniqueID: "T1059", enabled: true, ... }], ... }
 *
 * Extracts enabled technique IDs and sends them to the caller.
 */

import { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';

interface Props {
  onImport: (techniqueIds: string[], name: string) => void;
  onClose: () => void;
  title?: string;
  actionLabel?: string;
  targetLabel?: string;
}

interface NavigatorLayer {
  name?: string;
  domain?: string;
  techniques?: Array<{
    techniqueID: string;
    enabled?: boolean;
    color?: string;
    score?: number;
  }>;
}

export function LayerImport({
  onImport,
  onClose,
  title = 'Import Navigator Layer',
  actionLabel = 'Import',
  targetLabel = 'your TTP layer',
}: Props) {
  const [preview, setPreview] = useState<{ name: string; count: number; ids: string[] } | null>(null);
  const [error, setError] = useState('');

  const parseLayer = useCallback((raw: string): string[] => {
    const parsed: NavigatorLayer = JSON.parse(raw);
    if (!Array.isArray(parsed.techniques)) {
      throw new Error('No "techniques" array found in layer file.');
    }
    return parsed.techniques
      .filter((t) => t.enabled !== false && t.techniqueID)
      .map((t) => t.techniqueID.toUpperCase());
  }, []);

  const onDrop = useCallback(
    ([file]: File[]) => {
      setError('');
      setPreview(null);
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const raw = e.target?.result as string;
          const ids = parseLayer(raw);
          const parsed: NavigatorLayer = JSON.parse(raw);
          setPreview({
            name: parsed.name ?? file.name,
            count: ids.length,
            ids,
          });
        } catch (err) {
          setError(err instanceof Error ? err.message : 'Invalid layer file.');
        }
      };
      reader.readAsText(file);
    },
    [parseLayer]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'application/json': ['.json'] },
    maxFiles: 1,
  });

  const handleConfirm = () => {
    if (preview) {
      onImport(preview.ids, preview.name);
      onClose();
    }
  };

  return (
    // Backdrop
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-[480px] max-w-full p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-white font-semibold">{title}</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white text-lg">✕</button>
        </div>

        {/* Drop zone */}
        <div
          {...getRootProps()}
          className={`border-2 border-dashed rounded-lg p-10 text-center cursor-pointer transition-colors mb-4 ${
            isDragActive ? 'border-mitre-accent bg-mitre-accent/10' : 'border-gray-600 hover:border-gray-400'
          }`}
        >
          <input {...getInputProps()} />
          <div className="text-3xl mb-2">⬆</div>
          {isDragActive ? (
            <p className="text-gray-300 text-sm">Drop the .json file here</p>
          ) : (
            <>
              <p className="text-gray-400 text-sm">
                Drag & drop an ATT&CK Navigator <code className="text-gray-300">.json</code> layer
              </p>
              <p className="text-gray-600 text-xs mt-1">or click to browse</p>
            </>
          )}
        </div>

        {error && (
          <div className="text-red-400 text-xs bg-red-900/20 px-3 py-2 rounded mb-4">{error}</div>
        )}

        {preview && (
          <div className="bg-gray-800 rounded-lg p-4 mb-4">
            <div className="text-sm text-white font-medium mb-1">{preview.name}</div>
            <div className="text-xs text-gray-400 mb-3">
              {preview.count} technique{preview.count !== 1 ? 's' : ''} will be loaded into {targetLabel}
            </div>
            <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
              {preview.ids.slice(0, 40).map((id) => (
                <span key={id} className="text-[10px] font-mono bg-gray-700 text-gray-300 px-1.5 py-0.5 rounded">
                  {id}
                </span>
              ))}
              {preview.ids.length > 40 && (
                <span className="text-[10px] text-gray-500">+{preview.ids.length - 40} more</span>
              )}
            </div>
          </div>
        )}

        <div className="flex gap-2 justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={!preview}
            className="px-4 py-2 text-sm bg-mitre-accent hover:bg-red-600 text-white rounded disabled:opacity-40 transition-colors"
          >
            {actionLabel} {preview ? `(${preview.count})` : ''}
          </button>
        </div>
      </div>
    </div>
  );
}

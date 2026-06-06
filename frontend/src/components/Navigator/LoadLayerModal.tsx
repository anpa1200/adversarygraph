import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { layersApi } from '@/api/client';

interface Props {
  domain: string;
  onLoad: (techniqueIds: string[], name: string) => void;
  onClose: () => void;
}

export function LoadLayerModal({ domain, onLoad, onClose }: Props) {
  const qc = useQueryClient();

  const { data: layers = [], isLoading } = useQuery({
    queryKey: ['saved-layers', domain],
    queryFn: () => layersApi.list(domain),
    staleTime: 0,
  });

  const loadMutation = useMutation({
    mutationFn: (id: string) => layersApi.load(id),
    onSuccess: data => {
      onLoad(data.technique_ids ?? [], data.name);
      onClose();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => layersApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['saved-layers'] }),
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-md p-6"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-white font-semibold text-base">Load saved layer</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white text-lg leading-none">✕</button>
        </div>

        {isLoading && (
          <div className="text-gray-500 text-sm py-6 text-center">Loading…</div>
        )}

        {!isLoading && layers.length === 0 && (
          <div className="text-gray-600 text-sm py-6 text-center">
            No saved layers yet. Select techniques and click <span className="text-gray-400">↓ Save layer</span>.
          </div>
        )}

        {!isLoading && layers.length > 0 && (
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {layers.map(layer => (
              <div
                key={layer.id}
                className="flex items-center gap-3 p-3 rounded-lg bg-gray-800 hover:bg-gray-750 border border-gray-700 transition-colors"
              >
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-white truncate">{layer.name}</div>
                  <div className="text-[10px] text-gray-500 mt-0.5">
                    {layer.technique_count} technique{layer.technique_count !== 1 ? 's' : ''}
                    {' · '}
                    {layer.domain}
                    {' · '}
                    {layer.updated_at.slice(0, 10)}
                  </div>
                </div>
                <div className="flex gap-2 shrink-0">
                  <button
                    onClick={() => loadMutation.mutate(layer.id)}
                    disabled={loadMutation.isPending}
                    className="text-xs bg-mitre-accent hover:bg-red-600 disabled:opacity-40 text-white px-3 py-1 rounded transition-colors"
                  >
                    Load
                  </button>
                  <button
                    onClick={() => {
                      if (confirm(`Delete "${layer.name}"?`)) deleteMutation.mutate(layer.id);
                    }}
                    disabled={deleteMutation.isPending}
                    className="text-xs text-gray-500 hover:text-red-400 border border-gray-700 hover:border-red-700 px-2 py-1 rounded transition-colors"
                  >
                    ✕
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

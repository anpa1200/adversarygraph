import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { layersApi } from '@/api/client';

interface Props {
  techniqueIds: string[];
  domain: string;
  onClose: () => void;
  onSaved: () => void;
}

export function SaveLayerModal({ techniqueIds, domain, onClose, onSaved }: Props) {
  const [name, setName] = useState('');
  const qc = useQueryClient();

  const save = useMutation({
    mutationFn: () => layersApi.save(name.trim(), techniqueIds, domain),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['saved-layers'] });
      onSaved();
      onClose();
    },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-sm p-6"
        onClick={e => e.stopPropagation()}
      >
        <h2 className="text-white font-semibold text-base mb-1">Save layer</h2>
        <p className="text-xs text-gray-500 mb-4">
          {techniqueIds.length} technique{techniqueIds.length !== 1 ? 's' : ''} · {domain}
        </p>

        <label className="block text-xs text-gray-400 mb-1">Layer name</label>
        <input
          autoFocus
          type="text"
          value={name}
          onChange={e => setName(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && name.trim()) save.mutate(); }}
          placeholder="e.g. MuddyWater CTI analysis"
          maxLength={255}
          className="w-full bg-gray-800 text-sm text-gray-200 px-3 py-2 rounded border border-gray-600 focus:border-mitre-accent outline-none mb-4"
        />

        {save.isError && (
          <p className="text-xs text-red-400 mb-3">Save failed — try again.</p>
        )}

        <div className="flex gap-2 justify-end">
          <button
            onClick={onClose}
            className="text-xs text-gray-400 hover:text-white border border-gray-700 px-4 py-1.5 rounded transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() => save.mutate()}
            disabled={!name.trim() || save.isPending}
            className="text-xs bg-mitre-accent hover:bg-red-600 disabled:opacity-40 text-white px-4 py-1.5 rounded font-medium transition-colors"
          >
            {save.isPending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

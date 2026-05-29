import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAppStore } from '@/store';
import { aptApi } from '@/api/client';
import { Header } from '@/components/Layout/Header';

export function APTLibrary() {
  const { domain, version, addTechniques, setOverlayGroup } = useAppStore();
  const [search, setSearch] = useState('');
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);

  const { data: groups = [], isLoading } = useQuery({
    queryKey: ['apt-groups', domain, version, search],
    queryFn: () =>
      aptApi.groups({ domain, version: version ?? undefined, search: search || undefined }),
  });

  const { data: groupDetail, isLoading: detailLoading } = useQuery({
    queryKey: ['apt-group', selectedGroupId, domain, version],
    queryFn: () => aptApi.group(selectedGroupId!, domain, version ?? undefined),
    enabled: !!selectedGroupId,
  });

  return (
    <div className="flex flex-col h-full">
      <Header title="APT Library" />
      <div className="flex flex-1 overflow-hidden">

        {/* Group list */}
        <div className="w-72 border-r border-gray-700 flex flex-col shrink-0">
          <div className="p-3 border-b border-gray-700">
            <input
              type="text"
              placeholder="Search groups..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-gray-800 text-sm text-gray-200 px-3 py-2 rounded border border-gray-600 focus:border-mitre-accent outline-none"
            />
          </div>

          <div className="flex-1 overflow-y-auto">
            {isLoading ? (
              <div className="p-4 text-gray-400 text-sm">Loading groups...</div>
            ) : (
              groups.map((group) => (
                <button
                  key={group.attack_id}
                  onClick={() => setSelectedGroupId(group.attack_id)}
                  className={`w-full text-left px-4 py-3 border-b border-gray-800 hover:bg-gray-800 transition-colors ${
                    selectedGroupId === group.attack_id ? 'bg-gray-800 border-l-2 border-l-mitre-accent' : ''
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-white">{group.name}</span>
                    <span className="text-xs text-gray-500">{group.attack_id}</span>
                  </div>
                  <div className="text-xs text-gray-400 mt-0.5">
                    {group.technique_count} techniques
                    {group.aliases.length > 0 && ` · ${group.aliases.slice(0, 2).join(', ')}`}
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Group detail */}
        <div className="flex-1 overflow-y-auto p-6">
          {!selectedGroupId && (
            <div className="flex items-center justify-center h-48 text-gray-500">
              Select a group to view its TTP profile
            </div>
          )}

          {selectedGroupId && detailLoading && (
            <div className="text-gray-400">Loading...</div>
          )}

          {groupDetail && !detailLoading && (
            <div>
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h2 className="text-xl font-bold text-white">{groupDetail.name}</h2>
                  <div className="flex gap-2 mt-1 flex-wrap">
                    <span className="text-xs text-gray-400 bg-gray-800 px-2 py-0.5 rounded font-mono">
                      {groupDetail.attack_id}
                    </span>
                    {groupDetail.aliases.map((alias) => (
                      <span key={alias} className="text-xs text-gray-400 bg-gray-800 px-2 py-0.5 rounded">
                        {alias}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="flex gap-2 shrink-0">
                  <button
                    onClick={() => {
                      addTechniques(groupDetail.techniques.map((t) => t.attack_id));
                    }}
                    className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded transition-colors"
                  >
                    Add all to my TTPs
                  </button>
                  <button
                    onClick={() => setOverlayGroup(groupDetail.attack_id, groupDetail.name)}
                    className="text-xs bg-mitre-accent hover:bg-red-600 text-white px-3 py-1.5 rounded transition-colors"
                  >
                    Overlay on Navigator
                  </button>
                  <a
                    href={groupDetail.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-gray-400 hover:text-white border border-gray-600 px-3 py-1.5 rounded transition-colors"
                  >
                    ATT&CK ↗
                  </a>
                </div>
              </div>

              {groupDetail.description && (
                <p className="text-sm text-gray-400 mb-6 leading-relaxed line-clamp-4">
                  {groupDetail.description}
                </p>
              )}

              <div className="text-sm text-gray-300 mb-3 font-medium">
                {groupDetail.technique_count} Techniques Used
              </div>

              <div className="space-y-1">
                {groupDetail.techniques.map((tech) => (
                  <div
                    key={tech.attack_id}
                    className="flex items-start gap-3 p-2 rounded hover:bg-gray-800 transition-colors"
                  >
                    <span className="font-mono text-xs text-mitre-accent pt-0.5 shrink-0 w-20">
                      {tech.attack_id}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm text-white">{tech.name}</div>
                      <div className="flex gap-1 mt-0.5 flex-wrap">
                        {tech.tactics.map((t) => (
                          <span key={t} className="text-[10px] bg-gray-700 text-gray-300 px-1.5 rounded">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                    {tech.is_subtechnique && (
                      <span className="text-[10px] text-gray-500 pt-0.5 shrink-0">sub</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

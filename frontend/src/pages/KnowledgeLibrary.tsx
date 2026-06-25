import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { knowledgeApi } from '@/api/client';
import type { KnowledgeArticle, KnowledgeArticleDetail } from '@/api/client';
import { Header } from '@/components/Layout/Header';
import clsx from 'clsx';

const CATEGORIES: Array<{ id: string; label: string; icon: string }> = [
  { id: '',               label: 'All',           icon: '◉' },
  { id: 'cve',            label: 'CVEs',          icon: '⚠' },
  { id: 'psirt_analysis', label: 'PSIRT',         icon: '⬡' },
  { id: 'threat_actor',   label: 'Threat Actors', icon: '◈' },
  { id: 'vendor_report',  label: 'Vendor Reports', icon: '▣' },
  { id: 'research',       label: 'Research',      icon: '◎' },
  { id: 'strategy',       label: 'Strategy',      icon: '▤' },
];

const CATEGORY_COLORS: Record<string, string> = {
  cve:            'bg-red-950 text-red-400 border-red-900',
  psirt_analysis: 'bg-orange-950 text-orange-400 border-orange-900',
  threat_actor:   'bg-purple-950 text-purple-400 border-purple-900',
  vendor_report:  'bg-blue-950 text-blue-400 border-blue-900',
  research:       'bg-teal-950 text-teal-400 border-teal-900',
  strategy:       'bg-green-950 text-green-400 border-green-900',
};

function CategoryBadge({ category }: { category: string }) {
  const label = CATEGORIES.find(c => c.id === category)?.label ?? category;
  return (
    <span className={clsx('rounded border px-2 py-0.5 text-[10px] font-semibold', CATEGORY_COLORS[category] ?? 'bg-gray-800 text-gray-400 border-gray-700')}>
      {label}
    </span>
  );
}

function ArticleModal({ id, onClose }: { id: number; onClose: () => void }) {
  const { data, isLoading } = useQuery<KnowledgeArticleDetail>({
    queryKey: ['knowledge-article', id],
    queryFn: () => knowledgeApi.get(id),
  });

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70"
      onClick={onClose}
    >
      <div
        className="flex flex-col bg-gray-900 border border-gray-700 rounded-xl w-[92vw] max-w-4xl max-h-[90vh] overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-4 px-6 py-4 border-b border-gray-700 shrink-0">
          <div className="min-w-0">
            {data && <div className="mb-2"><CategoryBadge category={data.category} /></div>}
            <h2 className="text-lg font-semibold text-white leading-tight">
              {isLoading ? 'Loading…' : data?.title}
            </h2>
            {data?.tags && data.tags.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {data.tags.slice(0, 12).map(tag => (
                  <span key={tag} className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-400">{tag}</span>
                ))}
              </div>
            )}
          </div>
          <button
            onClick={onClose}
            className="shrink-0 rounded border border-gray-600 px-3 py-1.5 text-xs text-gray-400 hover:text-white hover:border-gray-400"
          >
            Close
          </button>
        </div>

        {/* Body — rendered markdown */}
        <div className="flex-1 overflow-y-auto px-6 py-5">
          {isLoading && <div className="text-sm text-gray-500">Loading article…</div>}
          {data && (
            <div className="prose prose-invert prose-sm max-w-none
              prose-headings:text-white prose-headings:font-semibold
              prose-h1:text-xl prose-h2:text-base prose-h3:text-sm
              prose-p:text-gray-300 prose-p:leading-relaxed
              prose-a:text-blue-400 prose-a:no-underline hover:prose-a:underline
              prose-code:bg-gray-800 prose-code:text-green-400 prose-code:px-1 prose-code:rounded prose-code:text-xs prose-code:before:content-none prose-code:after:content-none
              prose-pre:bg-gray-950 prose-pre:border prose-pre:border-gray-700 prose-pre:rounded prose-pre:text-xs
              prose-table:text-xs prose-th:text-gray-300 prose-td:text-gray-400
              prose-strong:text-gray-200
              prose-li:text-gray-300 prose-li:marker:text-gray-600
              prose-hr:border-gray-700
            ">
              <ReactMarkdown remarkPlugins={[remarkGfm]}>
                {data.body}
              </ReactMarkdown>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ArticleCard({ article, onClick }: { article: KnowledgeArticle; onClick: () => void }) {
  const cvss = article.meta?.cvss_score as number | undefined;
  const severity = article.meta?.severity as string | undefined;

  return (
    <button
      onClick={onClick}
      className="text-left w-full rounded-lg border border-gray-800 bg-gray-900/60 p-4 hover:border-gray-600 hover:bg-gray-800/60 transition-colors"
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <CategoryBadge category={article.category} />
        {cvss != null && (
          <span className={clsx('rounded px-2 py-0.5 text-[10px] font-bold', {
            'bg-red-950 text-red-300': (severity ?? '') === 'critical' || cvss >= 9,
            'bg-orange-950 text-orange-300': (severity ?? '') === 'high' || (cvss >= 7 && cvss < 9),
            'bg-yellow-950 text-yellow-300': (severity ?? '') === 'medium' || (cvss >= 4 && cvss < 7),
            'bg-gray-800 text-gray-400': cvss < 4,
          })}>
            CVSS {cvss}
          </span>
        )}
      </div>
      <h3 className="text-sm font-semibold text-white leading-snug mb-1">{article.title}</h3>
      {article.summary && (
        <p className="text-xs text-gray-400 leading-relaxed line-clamp-2">{article.summary}</p>
      )}
      {article.tags.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {article.tags.slice(0, 5).map(tag => (
            <span key={tag} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">{tag}</span>
          ))}
          {article.tags.length > 5 && (
            <span className="text-[10px] text-gray-600">+{article.tags.length - 5}</span>
          )}
        </div>
      )}
    </button>
  );
}

export function KnowledgeLibrary() {
  const qc = useQueryClient();
  const [params] = useSearchParams();
  const [category, setCategory] = useState('');
  const [q, setQ] = useState('');
  const [openId, setOpenId] = useState<number | null>(null);

  useEffect(() => {
    const qParam = params.get('q');
    if (qParam) setQ(qParam);
  }, [params]);

  const { data: stats } = useQuery({
    queryKey: ['knowledge-stats'],
    queryFn: knowledgeApi.stats,
  });

  const { data: articles = [], isLoading } = useQuery({
    queryKey: ['knowledge-articles', category, q],
    queryFn: () => knowledgeApi.list({ category: category || undefined, q: q || undefined, limit: 200 }),
  });

  const seed = useMutation({
    mutationFn: knowledgeApi.seed,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['knowledge-articles'] });
      qc.invalidateQueries({ queryKey: ['knowledge-stats'] });
    },
  });

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <Header title="Knowledge Library" />
      <div className="min-h-0 flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">

          {/* Stats bar */}
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div className="flex gap-3 flex-wrap">
              {stats && Object.entries(stats.by_category).map(([cat, count]) => {
                const def = CATEGORIES.find(c => c.id === cat);
                return (
                  <div key={cat} className="rounded border border-gray-800 bg-gray-900/60 px-3 py-2">
                    <div className="text-[10px] text-gray-500">{def?.label ?? cat}</div>
                    <div className="text-lg font-bold text-white">{count}</div>
                  </div>
                );
              })}
              {stats && (
                <div className="rounded border border-gray-700 bg-gray-800/60 px-3 py-2">
                  <div className="text-[10px] text-gray-400">Total</div>
                  <div className="text-lg font-bold text-mitre-accent">{stats.total}</div>
                </div>
              )}
            </div>
            <div className="flex items-center gap-2">
              {seed.data && (
                <span className="text-xs text-green-400">
                  ✓ Seeded {seed.data.inserted} new / {seed.data.skipped} existing
                </span>
              )}
              <button
                onClick={() => seed.mutate()}
                disabled={seed.isPending}
                className="rounded border border-gray-600 px-3 py-1.5 text-xs text-gray-400 hover:text-white hover:border-gray-400 disabled:opacity-50"
              >
                {seed.isPending ? 'Seeding…' : stats?.total === 0 ? 'Seed from files' : 'Re-seed'}
              </button>
            </div>
          </div>

          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <input
              type="search"
              placeholder="Search title, body…"
              value={q}
              onChange={e => setQ(e.target.value)}
              className="field w-64"
            />
            <div className="flex gap-1 flex-wrap">
              {CATEGORIES.map(cat => (
                <button
                  key={cat.id}
                  onClick={() => setCategory(cat.id)}
                  className={clsx(
                    'rounded border px-3 py-1.5 text-xs font-medium transition-colors',
                    category === cat.id
                      ? 'border-mitre-accent bg-mitre-accent/20 text-mitre-accent'
                      : 'border-gray-700 text-gray-400 hover:text-white'
                  )}
                >
                  {cat.icon} {cat.label}
                  {stats && cat.id && (
                    <span className="ml-1 text-[10px] text-gray-600">
                      {stats.by_category[cat.id] ?? 0}
                    </span>
                  )}
                </button>
              ))}
            </div>
          </div>

          {/* Empty state — prompt seed */}
          {!isLoading && articles.length === 0 && stats?.total === 0 && (
            <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-12 text-center">
              <div className="text-4xl mb-3">◎</div>
              <div className="text-white font-semibold mb-1">Knowledge base is empty</div>
              <div className="text-sm text-gray-500 mb-4">
                Click "Seed from files" above to load 39 NVIDIA intelligence articles.
              </div>
              <button
                onClick={() => seed.mutate()}
                disabled={seed.isPending}
                className="primary"
              >
                {seed.isPending ? 'Seeding…' : 'Seed Knowledge Base'}
              </button>
            </div>
          )}

          {/* Loading */}
          {isLoading && <div className="text-sm text-gray-500">Loading articles…</div>}

          {/* Articles grid */}
          {articles.length > 0 && (
            <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-3">
              {articles.map(article => (
                <ArticleCard
                  key={article.id}
                  article={article}
                  onClick={() => setOpenId(article.id)}
                />
              ))}
            </div>
          )}

          {/* No results after search */}
          {!isLoading && articles.length === 0 && (stats?.total ?? 0) > 0 && (
            <div className="text-center py-12 text-sm text-gray-500">
              No articles match your search. Try clearing filters.
            </div>
          )}

        </div>
      </div>

      {openId != null && (
        <ArticleModal id={openId} onClose={() => setOpenId(null)} />
      )}
    </div>
  );
}

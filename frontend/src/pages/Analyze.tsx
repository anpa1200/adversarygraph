import { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { useNavigate } from 'react-router-dom';
import { useAppStore } from '@/store';
import { analyzeApi, exportApi } from '@/api/client';
import type { AnalysisResult } from '@/api/client';
import { useSseStream } from '@/hooks/useSseStream';
import { Header } from '@/components/Layout/Header';

type Provider = 'claude' | 'openai' | 'gemini';

const PROVIDERS: { id: Provider; label: string; model: string; color: string }[] = [
  { id: 'claude',  label: 'Claude',  model: 'claude-opus-4-8',  color: 'border-orange-600 bg-orange-900/20 text-orange-300' },
  { id: 'openai',  label: 'GPT-4o',  model: 'gpt-4o',           color: 'border-green-700  bg-green-900/20  text-green-300'  },
  { id: 'gemini',  label: 'Gemini',  model: 'gemini-2.0-flash',  color: 'border-blue-600   bg-blue-900/20   text-blue-300'   },
];

export function Analyze() {
  const { domain, addTechniques } = useAppStore();
  const navigate = useNavigate();

  const [provider, setProvider] = useState<Provider>('claude');
  const [text,     setText]     = useState('');
  const [file,     setFile]     = useState<File | null>(null);

  // result: populated by the server-side "result" SSE event (includes APT matches)
  // tokens: raw LLM token stream shown live while waiting
  const { tokens, result, error, streaming, run, abort, reset } = useSseStream<AnalysisResult>();

  const handleRun = useCallback(async () => {
    const fd = new FormData();
    fd.append('provider', provider);
    fd.append('domain', domain);
    if (file) fd.append('file', file);
    else if (text.trim()) fd.append('text', text.trim());
    else return;

    reset();
    await run(analyzeApi.stream(fd));
  }, [provider, domain, file, text, run, reset]);

  const onDrop = useCallback(([f]: File[]) => { if (f) { setFile(f); setText(''); } }, []);
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'application/pdf': ['.pdf'], 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'], 'text/plain': ['.txt'] },
    maxFiles: 1,
  });

  const canSubmit = (!!text.trim() || !!file) && !streaming;

  return (
    <div className="flex flex-col h-full">
      <Header title="AI Analysis" />

      <div className="flex flex-1 overflow-hidden">

        {/* ── Left: input panel ─────────────────────────────────────────────── */}
        <div className="w-[380px] shrink-0 border-r border-gray-700 flex flex-col">

          {/* Provider selector */}
          <div className="p-4 border-b border-gray-800">
            <div className="text-xs text-gray-500 mb-2 font-semibold uppercase tracking-wide">LLM Provider</div>
            <div className="flex flex-col gap-1.5">
              {PROVIDERS.map(p => (
                <button
                  key={p.id}
                  onClick={() => setProvider(p.id)}
                  className={`flex items-center gap-3 px-3 py-2 rounded-lg border text-sm font-medium transition-colors ${
                    provider === p.id ? p.color : 'border-gray-700 text-gray-500 hover:text-gray-300'
                  }`}
                >
                  <span className="flex-1 text-left">{p.label}</span>
                  <span className="text-[10px] opacity-60 font-mono">{p.model}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Text input */}
          <div className="p-4 border-b border-gray-800 flex-1 flex flex-col">
            <div className="text-xs text-gray-500 mb-2 font-semibold uppercase tracking-wide">Paste text</div>
            <textarea
              value={text}
              onChange={e => { setText(e.target.value); setFile(null); }}
              rows={8}
              className="flex-1 bg-gray-800 text-xs text-gray-200 px-3 py-2 rounded border border-gray-700 focus:border-mitre-accent outline-none resize-none font-mono placeholder-gray-600"
              placeholder="Paste incident report, investigation notes, IOC list, threat intel blog…"
            />

            {/* File upload */}
            <div className="mt-3">
              <div className="text-xs text-gray-500 mb-2 font-semibold uppercase tracking-wide">Or upload (PDF / DOCX / TXT)</div>
              <div
                {...getRootProps()}
                className={`border-2 border-dashed rounded-lg p-4 text-center cursor-pointer transition-colors text-xs ${
                  isDragActive ? 'border-mitre-accent bg-mitre-accent/10' : 'border-gray-700 hover:border-gray-500'
                }`}
              >
                <input {...getInputProps()} />
                {file ? (
                  <div className="text-gray-300 flex items-center justify-center gap-2">
                    <span className="text-mitre-accent">✓</span>
                    <span>{file.name}</span>
                    <button className="text-gray-500 hover:text-red-400 text-xs" onClick={e => { e.stopPropagation(); setFile(null); }}>✕</button>
                  </div>
                ) : (
                  <p className="text-gray-600">{isDragActive ? 'Drop here' : 'Drag & drop or click'}</p>
                )}
              </div>
            </div>
          </div>

          {/* Submit */}
          <div className="p-4">
            {streaming ? (
              <button
                onClick={abort}
                className="w-full bg-gray-700 hover:bg-gray-600 text-white py-2.5 rounded font-medium text-sm transition-colors"
              >
                Stop analysis
              </button>
            ) : (
              <button
                onClick={handleRun}
                disabled={!canSubmit}
                className="w-full bg-mitre-accent hover:bg-red-600 disabled:opacity-40 text-white py-2.5 rounded font-medium text-sm transition-colors"
              >
                Analyse with AI
              </button>
            )}
            {error && (
              <div className="mt-3 text-xs text-red-400 bg-red-900/20 px-3 py-2 rounded">
                {error}
              </div>
            )}
          </div>
        </div>

        {/* ── Right: results panel ──────────────────────────────────────────── */}
        <div className="flex-1 flex flex-col overflow-hidden">

          {/* Live token stream */}
          {streaming && (
            <div className="border-b border-gray-800 bg-gray-900/50">
              <div className="flex items-center gap-2 px-4 py-2 border-b border-gray-800">
                <div className="w-2 h-2 rounded-full bg-mitre-accent animate-pulse" />
                <span className="text-xs text-gray-400">Analysing…</span>
              </div>
              <pre className="text-[10px] font-mono text-gray-400 px-4 py-3 max-h-40 overflow-y-auto whitespace-pre-wrap">
                {tokens || ' '}
              </pre>
            </div>
          )}

          {/* Empty state */}
          {!streaming && !tokens && !result && (
            <div className="flex-1 flex flex-col items-center justify-center text-center text-gray-600">
              <div className="text-5xl mb-4">⬢</div>
              <p className="text-gray-500">Submit a report to extract ATT&CK techniques.</p>
              <p className="text-xs mt-2 text-gray-600">
                Results auto-populate your Navigator layer.
              </p>
            </div>
          )}

          {/* Full parsed result from server (includes APT matches) */}
          {result && (
            <ResultsView
              result={result}
              domain={domain}
              addTechniques={addTechniques}
              navigate={navigate}
            />
          )}

          {/* Fallback: parse raw tokens when stream ended without a result event */}
          {!result && !streaming && tokens && (
            <StreamResultParser
              tokens={tokens}
              domain={domain}
              addTechniques={addTechniques}
              navigate={navigate}
            />
          )}
        </div>
      </div>
    </div>
  );
}

// ── Result view ───────────────────────────────────────────────────────────────

function ResultsView({
  result, domain, addTechniques, navigate,
}: {
  result: AnalysisResult;
  domain: string;
  addTechniques: (ids: string[]) => void;
  navigate: ReturnType<typeof useNavigate>;
}) {
  const [tab, setTab] = useState<'techniques' | 'groups' | 'raw'>('techniques');

  const injectAndNavigate = () => {
    addTechniques(result.techniques.map(t => t.attack_id));
    navigate('/navigator');
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Summary bar */}
      <div className="px-6 py-4 border-b border-gray-800 bg-gray-900/50">
        <div className="flex items-center justify-between mb-2">
          <div>
            <span className="text-xs text-gray-500 font-mono">{result.provider} / {result.model}</span>
          </div>
          <div className="flex gap-2">
            <a
              href={exportApi.analysisUrl(result.session_id)}
              download={`analysis-${result.session_id.slice(0, 8)}.pdf`}
              className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded transition-colors"
            >
              ↓ PDF report
            </a>
            <button
              onClick={injectAndNavigate}
              className="text-xs bg-mitre-accent hover:bg-red-600 text-white px-3 py-1.5 rounded transition-colors"
            >
              → Inject into Navigator
            </button>
          </div>
        </div>
        {result.summary && (
          <p className="text-sm text-gray-300 leading-relaxed">{result.summary}</p>
        )}
        {result.apt_hints.length > 0 && (
          <div className="flex gap-1.5 flex-wrap mt-2">
            <span className="text-xs text-gray-500">Mentioned:</span>
            {result.apt_hints.map(h => (
              <span key={h} className="text-xs bg-yellow-900/30 text-yellow-400 border border-yellow-800 px-2 py-0.5 rounded-full">{h}</span>
            ))}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-4 px-6 py-2 border-b border-gray-800 text-xs">
        <TabBtn active={tab === 'techniques'} onClick={() => setTab('techniques')}>
          Techniques ({result.techniques.length})
        </TabBtn>
        <TabBtn active={tab === 'groups'} onClick={() => setTab('groups')}>
          APT Matches ({result.apt_matches.length})
        </TabBtn>
        <TabBtn active={tab === 'raw'} onClick={() => setTab('raw')}>
          Raw response
        </TabBtn>
      </div>

      <div className="flex-1 overflow-y-auto px-6 py-4">
        {tab === 'techniques' && (
          <div className="space-y-2">
            {result.techniques.length === 0 && <p className="text-gray-500 text-sm">No techniques extracted.</p>}
            {result.techniques.map(t => (
              <div key={t.attack_id} className="flex gap-3 p-3 bg-gray-800 rounded-lg">
                <span className="font-mono text-xs text-mitre-accent pt-0.5 w-20 shrink-0">{t.attack_id}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm text-white font-medium">{t.name}</span>
                    <span className="text-[10px] bg-gray-700 text-gray-300 px-1.5 rounded">{t.tactic}</span>
                    <ConfidenceBadge value={t.confidence} />
                  </div>
                  {t.evidence && <p className="text-xs text-gray-500 mt-1 italic">"{t.evidence}"</p>}
                </div>
              </div>
            ))}
          </div>
        )}

        {tab === 'groups' && (
          <div className="space-y-2">
            {result.apt_matches.length === 0 && <p className="text-gray-500 text-sm">No APT group matches.</p>}
            {result.apt_matches.map((m, i) => (
              <div key={m.group_attack_id} className="p-3 bg-gray-800 rounded-lg">
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-600 w-5">#{i + 1}</span>
                  <div className="w-24 bg-gray-700 rounded-full h-1.5">
                    <div className="bg-mitre-accent h-1.5 rounded-full" style={{ width: `${m.similarity * 100}%` }} />
                  </div>
                  <span className="text-sm font-medium text-white flex-1">{m.group_name}</span>
                  <span className="text-xs font-mono text-gray-500">{m.group_attack_id}</span>
                  <span className="text-xs text-mitre-accent font-mono">{Math.round(m.similarity * 100)}%</span>
                  <span className="text-xs text-gray-500">{m.shared_count} shared</span>
                </div>
                {m.shared_techniques.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2 ml-8">
                    {m.shared_techniques.map(id => (
                      <span key={id} className="text-[10px] font-mono bg-mitre-accent/10 text-mitre-accent px-1.5 py-0.5 rounded">
                        {id}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {tab === 'raw' && (
          <pre className="text-[10px] font-mono text-gray-400 whitespace-pre-wrap bg-gray-900 p-4 rounded-lg overflow-x-auto">
            {JSON.stringify(result, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}

// Parses stream tokens into a result when no explicit result event arrived
function StreamResultParser({
  tokens, domain, addTechniques, navigate,
}: {
  tokens: string;
  domain: string;
  addTechniques: (ids: string[]) => void;
  navigate: ReturnType<typeof useNavigate>;
}) {
  try {
    let cleaned = tokens.trim().replace(/^```(?:json)?\s*/m, '').replace(/\s*```$/m, '');
    const data = JSON.parse(cleaned);
    const result: AnalysisResult = {
      session_id: 'stream',
      provider: 'stream',
      model: '',
      summary: data.summary || '',
      techniques: (data.techniques || []).map((t: Record<string, unknown>) => ({
        attack_id: String(t.attack_id || '').toUpperCase(),
        name: String(t.name || ''),
        tactic: String(t.tactic || ''),
        confidence: Number(t.confidence || 0.5),
        evidence: String(t.evidence || ''),
      })),
      apt_matches: [],
      apt_hints: data.apt_hints || [],
    };
    return <ResultsView result={result} domain={domain} addTechniques={addTechniques} navigate={navigate} />;
  } catch {
    // Couldn't parse yet — show raw
    return (
      <div className="flex-1 overflow-y-auto p-6">
        <pre className="text-[10px] font-mono text-gray-400 whitespace-pre-wrap">{tokens}</pre>
      </div>
    );
  }
}

// ── Sub-components ────────────────────────────────────────────────────────────

function TabBtn({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`pb-1.5 border-b-2 transition-colors ${
        active ? 'border-mitre-accent text-white' : 'border-transparent text-gray-500 hover:text-gray-300'
      }`}
    >
      {children}
    </button>
  );
}

function ConfidenceBadge({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const cls = pct >= 80 ? 'bg-green-900/50 text-green-400' : pct >= 50 ? 'bg-yellow-900/50 text-yellow-400' : 'bg-gray-700 text-gray-400';
  return <span className={`text-[10px] px-1.5 py-0.5 rounded ${cls}`}>{pct}%</span>;
}

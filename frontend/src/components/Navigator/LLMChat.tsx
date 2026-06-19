/**
 * Compact chat widget for the technique panel and any other embedded use.
 * Streams tokens from POST /api/analyze/chat via SSE.
 * Keeps a local message history (session-scoped, not persisted).
 */

import { useState, useRef, useEffect, useCallback } from 'react';
import { analyzeApi } from '@/api/client';
import { useSseStream } from '@/hooks/useSseStream';

type Provider = 'claude' | 'openai' | 'gemini' | 'minimax' | 'local';

const PROVIDERS: { id: Provider; short: string }[] = [
  { id: 'claude',  short: 'Claude' },
  { id: 'openai',  short: 'OpenAI' },
  { id: 'gemini',  short: 'Gemini' },
  { id: 'minimax', short: 'MiniMax' },
  { id: 'local',   short: 'Local' },
];

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

interface Props {
  initialContext?: string;   // prepended to first message as context
  placeholder?: string;
}

export function LLMChat({ initialContext, placeholder = 'Ask the AI assistant…' }: Props) {
  const [provider, setProvider] = useState<Provider>('claude');
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<Message[]>([]);
  const bottomRef = useRef<HTMLDivElement>(null);

  const { tokens, result: _r, error, streaming, run, abort, reset } = useSseStream<never>();

  // Scroll to bottom on new content
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [tokens, history]);

  // When streaming ends, commit the assistant message to history
  const prevStreaming = useRef(false);
  useEffect(() => {
    if (prevStreaming.current && !streaming && tokens) {
      setHistory(h => [...h, { role: 'assistant', content: tokens }]);
      reset();
    }
    prevStreaming.current = streaming;
  }, [streaming, tokens, reset]);

  const send = useCallback(async () => {
    const msg = input.trim();
    if (!msg || streaming) return;
    setInput('');
    setHistory(h => [...h, { role: 'user', content: msg }]);

    const context = history.length === 0 && initialContext
      ? initialContext
      : history.map(m => `${m.role === 'user' ? 'Analyst' : 'AI'}: ${m.content}`).join('\n');

    await run(
      analyzeApi.chat({ message: msg, provider, context })
    );
  }, [input, streaming, history, initialContext, provider, run]);

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  return (
    <div className="border-t border-gray-700 flex flex-col">
      {/* Chat header */}
      <div className="flex items-center gap-2 px-4 py-2 bg-gray-800/50">
        <span className="text-[10px] text-gray-400 font-semibold uppercase tracking-wide">AI Assistant</span>
        <div className="ml-auto flex gap-1">
          {PROVIDERS.map(p => (
            <button
              key={p.id}
              onClick={() => setProvider(p.id)}
              className={`text-[10px] px-2 py-0.5 rounded transition-colors ${
                provider === p.id
                  ? 'bg-mitre-accent text-white'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              {p.short}
            </button>
          ))}
        </div>
      </div>

      {/* Message history */}
      <div className="px-4 py-2 space-y-3 max-h-64 overflow-y-auto text-xs">
        {history.length === 0 && !streaming && (
          <p className="text-gray-600 text-center py-4">
            Ask anything about this technique, TTPs, or threat actors.
          </p>
        )}

        {history.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div
              className={`max-w-[85%] rounded-lg px-3 py-2 leading-relaxed whitespace-pre-wrap ${
                msg.role === 'user'
                  ? 'bg-mitre-accent/20 text-gray-200'
                  : 'bg-gray-800 text-gray-300'
              }`}
            >
              {msg.content}
            </div>
          </div>
        ))}

        {/* Live streaming message */}
        {streaming && tokens && (
          <div className="flex justify-start">
            <div className="max-w-[85%] bg-gray-800 text-gray-300 rounded-lg px-3 py-2 text-xs leading-relaxed whitespace-pre-wrap">
              {tokens}
              <span className="inline-block w-1 h-3 ml-0.5 bg-mitre-accent animate-pulse align-middle" />
            </div>
          </div>
        )}

        {streaming && !tokens && (
          <div className="flex justify-start">
            <div className="bg-gray-800 rounded-lg px-3 py-2">
              <span className="flex gap-1">
                {[0, 1, 2].map(i => (
                  <span
                    key={i}
                    className="w-1.5 h-1.5 bg-gray-500 rounded-full animate-bounce"
                    style={{ animationDelay: `${i * 0.15}s` }}
                  />
                ))}
              </span>
            </div>
          </div>
        )}

        {error && (
          <div className="text-red-400 text-[10px] bg-red-900/20 px-2 py-1 rounded">{error}</div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="flex gap-2 px-4 py-3 border-t border-gray-800">
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          rows={2}
          placeholder={placeholder}
          disabled={streaming}
          className="flex-1 bg-gray-800 text-xs text-gray-200 px-3 py-2 rounded border border-gray-700 focus:border-mitre-accent outline-none resize-none placeholder-gray-600 disabled:opacity-50"
        />
        {streaming ? (
          <button
            onClick={abort}
            className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs rounded transition-colors"
          >
            Stop
          </button>
        ) : (
          <button
            onClick={send}
            disabled={!input.trim()}
            className="px-3 py-2 bg-mitre-accent hover:bg-red-600 disabled:opacity-30 text-white text-xs rounded transition-colors"
          >
            Send
          </button>
        )}
      </div>
    </div>
  );
}

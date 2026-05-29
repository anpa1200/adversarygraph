/**
 * Consumes a fetch() Response that streams SSE events.
 *
 * Events expected:
 *   data: {"type":"token","content":"..."}
 *   data: {"type":"result","data":{...}}
 *   data: {"type":"done"}
 *   data: {"type":"error","message":"..."}
 */

import { useCallback, useRef, useState } from 'react';

interface SseState<T> {
  tokens: string;          // accumulated streaming text
  result: T | null;        // final parsed result (when "result" event arrives)
  error: string;
  streaming: boolean;
}

export function useSseStream<T>() {
  const [state, setState] = useState<SseState<T>>({
    tokens: '',
    result: null,
    error: '',
    streaming: false,
  });
  const abortRef = useRef<AbortController | null>(null);

  const run = useCallback(async (responsePromise: Promise<Response>) => {
    abortRef.current?.abort();
    abortRef.current = new AbortController();

    setState({ tokens: '', result: null, error: '', streaming: true });

    try {
      const resp = await responsePromise;
      if (!resp.ok || !resp.body) {
        const text = await resp.text();
        setState(s => ({ ...s, error: text || 'Request failed', streaming: false }));
        return;
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop() ?? '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const raw = line.slice(6);
          if (raw === '[DONE]') break;

          try {
            const evt = JSON.parse(raw);
            if (evt.type === 'token') {
              setState(s => ({ ...s, tokens: s.tokens + evt.content }));
            } else if (evt.type === 'result') {
              setState(s => ({ ...s, result: evt.data as T }));
            } else if (evt.type === 'error') {
              setState(s => ({ ...s, error: evt.message, streaming: false }));
              return;
            }
          } catch {
            // skip malformed line
          }
        }
      }

      setState(s => ({ ...s, streaming: false }));
    } catch (err) {
      if ((err as Error).name !== 'AbortError') {
        setState(s => ({ ...s, error: String(err), streaming: false }));
      }
    }
  }, []);

  const abort = useCallback(() => {
    abortRef.current?.abort();
    setState(s => ({ ...s, streaming: false }));
  }, []);

  const reset = useCallback(() => {
    setState({ tokens: '', result: null, error: '', streaming: false });
  }, []);

  return { ...state, run, abort, reset };
}

/**
 * Consumes a fetch() Response that streams SSE events.
 *
 * Events expected:
 *   data: {"type":"token","content":"..."}
 *   data: {"type":"result","data":{...}}
 *   data: {"type":"done"}
 *   data: {"type":"error","message":"..."}
 */

import { useCallback, useEffect, useRef, useState } from 'react';

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
  const requestIdRef = useRef(0);

  const run = useCallback(async (responseFactory: (signal: AbortSignal) => Promise<Response>) => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    const requestId = ++requestIdRef.current;

    setState({ tokens: '', result: null, error: '', streaming: true });

    try {
      const resp = await responseFactory(controller.signal);
      if (requestId !== requestIdRef.current) {
        await resp.body?.cancel().catch(() => undefined);
        return;
      }
      if (!resp.ok || !resp.body) {
        const text = await resp.text();
        if (requestId === requestIdRef.current) {
          setState(s => ({ ...s, error: text || 'Request failed', streaming: false }));
        }
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
          if (requestId !== requestIdRef.current) {
            await reader.cancel().catch(() => undefined);
            return;
          }
          if (!line.startsWith('data: ')) continue;
          const raw = line.slice(6);
          if (raw === '[DONE]') {
            await reader.cancel().catch(() => undefined);
            if (requestId === requestIdRef.current) {
              setState(s => ({ ...s, streaming: false }));
            }
            return;
          }

          try {
            const evt = JSON.parse(raw);
            if (evt.type === 'token') {
              setState(s => ({ ...s, tokens: s.tokens + evt.content }));
            } else if (evt.type === 'result') {
              setState(s => ({ ...s, result: evt.data as T }));
            } else if (evt.type === 'done') {
              await reader.cancel().catch(() => undefined);
              if (requestId === requestIdRef.current) {
                setState(s => ({ ...s, streaming: false }));
              }
              return;
            } else if (evt.type === 'error') {
              await reader.cancel().catch(() => undefined);
              setState(s => ({ ...s, error: evt.message, streaming: false }));
              return;
            }
          } catch {
            // skip malformed line
          }
        }
      }

      if (requestId === requestIdRef.current) {
        setState(s => ({ ...s, streaming: false }));
      }
    } catch (err) {
      if ((err as Error).name !== 'AbortError' && requestId === requestIdRef.current) {
        setState(s => ({ ...s, error: String(err), streaming: false }));
      }
    } finally {
      if (requestId === requestIdRef.current) abortRef.current = null;
    }
  }, []);

  const abort = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    requestIdRef.current += 1;
    setState(s => ({ ...s, streaming: false }));
  }, []);

  const reset = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    requestIdRef.current += 1;
    setState({ tokens: '', result: null, error: '', streaming: false });
  }, []);

  useEffect(() => () => {
    requestIdRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
  }, []);

  return { ...state, run, abort, reset };
}

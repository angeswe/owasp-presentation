import { useState, useCallback, useRef } from 'react';

interface StreamState {
  text: string;
  isStreaming: boolean;
  isThinking: boolean;
  error: string | null;
}

const API_BASE = 'http://localhost:3001/api';

export function useLLMStream() {
  const [state, setState] = useState<StreamState>({
    text: '',
    isStreaming: false,
    isThinking: false,
    error: null,
  });
  const abortRef = useRef<AbortController | null>(null);

  const startStream = useCallback(async (endpoint: string, body?: Record<string, any>) => {
    // Abort any existing stream
    if (abortRef.current) {
      abortRef.current.abort();
    }

    const controller = new AbortController();
    abortRef.current = controller;

    setState({ text: '', isStreaming: true, isThinking: true, error: null });

    try {
      const url = `${API_BASE}${endpoint}`;
      const response = await fetch(url, {
        method: body ? 'POST' : 'GET',
        headers: body ? { 'Content-Type': 'application/json' } : {},
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({ error: response.statusText }));
        setState(prev => ({ ...prev, isStreaming: false, isThinking: false, error: errData.error || 'Request failed' }));
        return;
      }

      const reader = response.body?.getReader();
      if (!reader) {
        setState(prev => ({ ...prev, isStreaming: false, isThinking: false, error: 'Streaming not supported' }));
        return;
      }

      const decoder = new TextDecoder();
      let accumulated = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6).trim();
            if (data === '[DONE]') {
              setState(prev => ({ ...prev, isStreaming: false, isThinking: false }));
              return;
            }
            try {
              const parsed = JSON.parse(data);
              if (parsed.token !== undefined) {
                accumulated += parsed.token;
                setState(prev => ({ ...prev, text: accumulated, isThinking: false }));
              }
            } catch {
              // Skip malformed JSON
            }
          }
        }
      }

      setState(prev => ({ ...prev, isStreaming: false, isThinking: false }));
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        setState(prev => ({ ...prev, isStreaming: false, isThinking: false, error: err.message }));
      }
    }
  }, []);

  const stopStream = useCallback(() => {
    if (abortRef.current) {
      abortRef.current.abort();
      abortRef.current = null;
    }
    setState(prev => ({ ...prev, isStreaming: false, isThinking: false }));
  }, []);

  const reset = useCallback(() => {
    stopStream();
    setState({ text: '', isStreaming: false, isThinking: false, error: null });
  }, [stopStream]);

  return { ...state, startStream, stopStream, reset };
}

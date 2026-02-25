import { Response } from 'express';

/**
 * Streams a text response token-by-token via Server-Sent Events,
 * simulating LLM-style output.
 */
export function streamResponse(
  res: Response,
  text: string,
  delayMs: number = 50
): Promise<void> {
  return new Promise((resolve) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.flushHeaders();

    const tokens = text.split(/(\s+)/);
    let index = 0;

    const interval = setInterval(() => {
      if (index < tokens.length) {
        const token = tokens[index];
        res.write(`data: ${JSON.stringify({ token })}\n\n`);
        index++;
      } else {
        res.write('data: [DONE]\n\n');
        clearInterval(interval);
        res.end();
        resolve();
      }
    }, delayMs);

    res.on('close', () => {
      clearInterval(interval);
      resolve();
    });
  });
}

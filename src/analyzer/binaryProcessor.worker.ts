import { processBinaryFileChunked } from './binaryProcessor.js';

self.onmessage = async (e: MessageEvent) => {
  const { file, fileName } = e.data;
  try {
    const result = await processBinaryFileChunked(file, fileName, (percent, status) => {
      self.postMessage({ type: 'progress', percent, status });
    });
    self.postMessage({ type: 'success', result });
  } catch (error: any) {
    self.postMessage({ type: 'error', error: error.message || String(error) });
  }
};

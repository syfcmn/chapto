/// <reference types="vite/client" />

declare global {
  interface Window {
    pako: {
      deflate: (input: string, options?: { level?: number }) => Uint8Array;
      inflate: (input: Uint8Array, options?: { to?: string }) => string;
    };
    sodium: any;
    Module?: {
      locateFile?: (path: string) => string;
    };
  }
}

export {};

declare module 'postcss-safe-parser' {
  import type { Root } from 'postcss';

  export default function safeParser(css: string, options?: { from?: string }): Root;
}

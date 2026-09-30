/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Header carrying the API key (auth.api_key_header); defaults to X-API-Key. */
  readonly VITE_API_KEY_HEADER?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

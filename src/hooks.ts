import * as React from "react";
import type { Application } from "./types/argocd";

export interface AsyncState<T> {
  data?: T;
  error?: Error;
  loading: boolean;
}

interface Result<T> {
  key: string;
  data?: T;
  error?: Error;
}

/**
 * Runs `load` whenever `key` changes. Results are stored together with the key
 * they belong to, so a result for a previous key is never mistaken for the
 * current one. With `keepPrevious`, the last data stays visible while a new key
 * loads, which avoids flicker on periodic refreshes.
 */
export function useAsync<T>(load: () => Promise<T>, key: string, keepPrevious = false): AsyncState<T> {
  const [result, setResult] = React.useState<Result<T>>();
  const loadRef = React.useRef(load);

  React.useEffect(() => {
    loadRef.current = load;
  });

  React.useEffect(() => {
    let active = true;
    loadRef.current().then(
      (data) => {
        if (active) setResult({ key, data });
      },
      (error: unknown) => {
        if (active) setResult({ key, error: error instanceof Error ? error : new Error(String(error)) });
      },
    );
    return () => {
      active = false;
    };
  }, [key]);

  const current = result?.key === key;
  return {
    data: current || keepPrevious ? result?.data : undefined,
    error: current ? result.error : undefined,
    loading: !current,
  };
}

/** Identifies an application across namespaces, for use in `useAsync` keys. */
export function appKey(app: Application): string {
  return `${app.metadata.namespace ?? ""}/${app.metadata.name}`;
}

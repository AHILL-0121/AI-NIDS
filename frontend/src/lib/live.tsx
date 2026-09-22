"use client";

/**
 * Live updates: one WebSocket to /api/ws feeds the React Query cache, so every screen updates
 * from the same source of truth without polling (audit UI-01). Reconnects with backoff.
 */
import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

import type { Schemas } from "@/lib/api/client";

export type ConnectionState = "connecting" | "live" | "offline";

type Bucket = Schemas["Bucket"];
type AlertOut = Schemas["AlertOut"];

export type LiveEvent =
  | { type: "hello"; data: { user: string; server_time: number } }
  | { type: "alert.new" | "alert.updated"; data: AlertOut }
  | { type: "stats.tick"; data: Bucket }
  | { type: "sensor.state"; data: Record<string, unknown> }
  | {
      type: "job.progress";
      data: { id: string; kind: string; status: string; result: Record<string, unknown> };
    };

export const LIVE_TRAFFIC_KEY = ["live", "traffic"] as const;
const MAX_TICKS = 900; // 15 minutes of 1-second buckets

/** Apply one event to the query cache. Pure with respect to its inputs; exported for tests. */
export function applyEvent(queryClient: QueryClient, event: LiveEvent): void {
  switch (event.type) {
    case "alert.new":
    case "alert.updated": {
      queryClient.setQueryData(["alert", event.data.id], event.data);
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["summary"] });
      break;
    }
    case "stats.tick": {
      queryClient.setQueryData<Bucket[]>(LIVE_TRAFFIC_KEY, (previous = []) => {
        const next = [...previous.filter((b) => b.ts !== event.data.ts), event.data];
        next.sort((a, b) => a.ts - b.ts);
        return next.slice(-MAX_TICKS);
      });
      break;
    }
    case "sensor.state":
      void queryClient.invalidateQueries({ queryKey: ["sensor"] });
      void queryClient.invalidateQueries({ queryKey: ["sessions"] });
      break;
    case "job.progress":
      void queryClient.invalidateQueries({ queryKey: ["jobs"] });
      if (event.data.status === "done")
        void queryClient.invalidateQueries({ queryKey: ["models"] });
      break;
    default:
      break;
  }
}

/** ws:// URL for the API. In development the Next dev server (port 3000) doesn't proxy
 * WebSockets, so connect to the backend directly (set NIDS_ALLOWED_ORIGINS on the backend). */
export function socketUrl(location: Location): string {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  const override = process.env.NEXT_PUBLIC_NIDS_WS_URL;
  if (override) return override;
  if (process.env.NODE_ENV === "development" && location.port === "3000") {
    return `${scheme}//${location.hostname}:8000/api/ws`;
  }
  return `${scheme}//${location.host}/api/ws`;
}

const LiveContext = createContext<ConnectionState>("connecting");

export function LiveProvider({ children, enabled }: { children: ReactNode; enabled: boolean }) {
  const queryClient = useQueryClient();
  const [state, setState] = useState<ConnectionState>("connecting");

  useEffect(() => {
    if (!enabled) return;
    let socket: WebSocket | null = null;
    let retry = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let closed = false;

    const connect = () => {
      setState("connecting");
      socket = new WebSocket(socketUrl(window.location));
      socket.onopen = () => {
        retry = 0;
        setState("live");
      };
      socket.onmessage = (message) => {
        try {
          applyEvent(queryClient, JSON.parse(String(message.data)) as LiveEvent);
        } catch {
          // ignore malformed messages
        }
      };
      socket.onclose = () => {
        if (closed) return;
        setState("offline");
        retry = Math.min(retry + 1, 6);
        timer = setTimeout(connect, 500 * 2 ** retry); // 1 s, 2 s, ... up to 32 s
      };
    };
    connect();
    return () => {
      closed = true;
      clearTimeout(timer);
      socket?.close();
    };
  }, [enabled, queryClient]);

  return <LiveContext value={enabled ? state : "offline"}>{children}</LiveContext>;
}

export function useConnection(): ConnectionState {
  return useContext(LiveContext);
}

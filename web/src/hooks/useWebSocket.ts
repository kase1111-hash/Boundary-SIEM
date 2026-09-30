import { useEffect, useRef, useState, useCallback } from "react";
import { getApiKey, handleUnauthorized, subscribeAuth } from "../services/auth";
import { EventSocket, type WSStatus } from "../services/wsClient";

export type { WSStatus } from "../services/wsClient";

interface UseWebSocketOptions {
  url?: string;
  onMessage?: (data: unknown) => void;
  reconnectInterval?: number;
  maxReconnectInterval?: number;
  heartbeatInterval?: number;
  enabled?: boolean;
}

function defaultUrl(): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/ws/events`;
}

/**
 * Connects to the live event stream, authenticating with the stored API key
 * (see services/wsClient.ts for the protocol). Reconnects when the key
 * changes; a rejected key triggers the API key prompt.
 */
export function useWebSocket(options: UseWebSocketOptions = {}) {
  const {
    url,
    onMessage,
    reconnectInterval = 2000,
    maxReconnectInterval = 30000,
    heartbeatInterval = 30000,
    enabled = true,
  } = options;

  const [status, setStatus] = useState<WSStatus>("disconnected");
  const [lastMessage, setLastMessage] = useState<unknown>(null);
  const socketRef = useRef<EventSocket | null>(null);

  // Keep the latest callback without reconnecting when it changes identity
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    if (!enabled) return;

    let keyUsed: string | null = null;
    const socket = new EventSocket({
      url: url ?? defaultUrl(),
      getApiKey: () => {
        keyUsed = getApiKey();
        return keyUsed;
      },
      onStatus: setStatus,
      onMessage: (data) => {
        setLastMessage(data);
        onMessageRef.current?.(data);
      },
      onUnauthorized: (reason) => handleUnauthorized(keyUsed, reason),
      reconnectInterval,
      maxReconnectInterval,
      heartbeatInterval,
    });
    socketRef.current = socket;
    socket.start();

    const unsubscribe = subscribeAuth((event) => {
      if (event.type === "changed") socket.reconnectNow();
    });

    return () => {
      unsubscribe();
      socket.stop();
      socketRef.current = null;
    };
  }, [enabled, url, reconnectInterval, maxReconnectInterval, heartbeatInterval]);

  const send = useCallback((data: unknown) => {
    socketRef.current?.send(data);
  }, []);

  return { status, lastMessage, send };
}

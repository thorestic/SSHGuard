import {
  createContext,
  type PropsWithChildren,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

import { apiUrl } from "../api/client";

export type LiveConnectionStatus =
  | "connecting"
  | "live"
  | "reconnecting"
  | "offline";

interface LiveUpdatesState {
  lastEventAt: string | null;
  revision: number;
  status: LiveConnectionStatus;
}

const LiveUpdatesContext = createContext<LiveUpdatesState | null>(null);

export function LiveUpdatesProvider({ children }: PropsWithChildren) {
  const [status, setStatus] = useState<LiveConnectionStatus>("connecting");
  const [revision, setRevision] = useState(0);
  const [lastEventAt, setLastEventAt] = useState<string | null>(null);

  useEffect(() => {
    const source = new EventSource(apiUrl("/events/stream"));
    let offlineTimer: number | undefined;

    const clearOfflineTimer = () => {
      if (offlineTimer !== undefined) {
        window.clearTimeout(offlineTimer);
        offlineTimer = undefined;
      }
    };

    const markLive = () => {
      clearOfflineTimer();
      setStatus("live");
    };

    source.onopen = markLive;

    source.addEventListener("ready", () => {
      markLive();
      setLastEventAt(new Date().toISOString());
      setRevision((value) => value + 1);
    });

    source.addEventListener("security_update", () => {
      markLive();
      setLastEventAt(new Date().toISOString());
      setRevision((value) => value + 1);
    });

    source.addEventListener("unavailable", () => {
      clearOfflineTimer();
      setStatus("offline");
    });

    source.onerror = () => {
      setStatus("reconnecting");
      clearOfflineTimer();
      offlineTimer = window.setTimeout(
        () => setStatus("offline"),
        10_000,
      );
    };

    return () => {
      clearOfflineTimer();
      source.close();
    };
  }, []);

  const value = useMemo(
    () => ({ lastEventAt, revision, status }),
    [lastEventAt, revision, status],
  );

  return (
    <LiveUpdatesContext.Provider value={value}>
      {children}
    </LiveUpdatesContext.Provider>
  );
}

export function useLiveUpdates(): LiveUpdatesState {
  const context = useContext(LiveUpdatesContext);

  if (context === null) {
    throw new Error(
      "useLiveUpdates must be used inside LiveUpdatesProvider",
    );
  }

  return context;
}

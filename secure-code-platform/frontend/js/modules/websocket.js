// ============================================================================
// Live scan progress — prefers a WebSocket connection to the backend, and
// transparently falls back to polling GET /scan/{id}/progress every 1.5s if
// the socket fails to connect or errors out (some networks/proxies block
// websockets entirely). Callers don't need to know which transport is active.
// ============================================================================
import { API_BASE, api, getAccessToken } from "./api.js";

const POLL_INTERVAL_MS = 1500;

/**
 * @param {string} scanId
 * @param {{onLogs: (logs: any[]) => void, onStatus: (status: any) => void, onDone: () => void}} handlers
 * @returns {() => void} a cleanup function — call it to stop watching (e.g. on page unload)
 */
export function watchScanProgress(scanId, { onLogs, onStatus, onDone }) {
  let stopped = false;
  let socket = null;
  let pollTimer = null;

  const wsBase = API_BASE.replace(/^http/, "ws").replace(/\/api\/v1$/, "");
  const wsUrl = `${wsBase}/ws/scan/${scanId}?token=${encodeURIComponent(getAccessToken() || "")}`;

  function startPolling() {
    if (pollTimer || stopped) return;
    const poll = async () => {
      if (stopped) return;
      try {
        const progress = await api.get(`/scan/${scanId}/progress`);
        if (progress.logs?.length) onLogs(progress.logs);
        onStatus(progress);
        if (["completed", "failed", "cancelled"].includes(progress.status)) {
          stop();
          onDone();
          return;
        }
      } catch {
        /* transient network errors during polling are ignored — next tick retries */
      }
      pollTimer = setTimeout(poll, POLL_INTERVAL_MS);
    };
    poll();
  }

  function stop() {
    stopped = true;
    if (socket) {
      socket.onclose = null; // avoid triggering the fallback-to-polling logic on an intentional close
      socket.close();
    }
    if (pollTimer) clearTimeout(pollTimer);
  }

  try {
    socket = new WebSocket(wsUrl);
    let receivedAnyMessage = false;

    socket.onmessage = (event) => {
      receivedAnyMessage = true;
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === "logs") onLogs(msg.logs);
        if (msg.type === "status") {
          onStatus(msg);
          if (["completed", "failed", "cancelled"].includes(msg.status)) {
            stop();
            onDone();
          }
        }
      } catch {
        /* ignore malformed frames */
      }
    };

    socket.onerror = () => {
      if (!receivedAnyMessage && !stopped) startPolling();
    };

    socket.onclose = () => {
      if (!receivedAnyMessage && !stopped) startPolling();
    };
  } catch {
    startPolling();
  }

  return stop;
}

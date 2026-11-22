import { useEffect, useState } from "react";
import { verifyAudit } from "./api";
import AboutPanel from "./components/AboutPanel";
import AuditChainBadge from "./components/AuditChainBadge";
import EntropyChart from "./components/EntropyChart";
import HeaderStatus from "./components/HeaderStatus";
import IntelPanel from "./components/IntelPanel";
import ReportPanel from "./components/ReportPanel";
import RiskMatrix from "./components/RiskMatrix";
import ScanQueueFeed from "./components/ScanQueueFeed";
import ThreatCounters from "./components/ThreatCounters";
import ThreatLogTable from "./components/ThreatLogTable";
import VaultPanel from "./components/VaultPanel";
import { useAegisSocket } from "./hooks/useAegisSocket";

type Tab = "live" | "intel" | "integrity" | "about";
const TABS: { id: Tab; label: string }[] = [
  { id: "live", label: "Live" },
  { id: "intel", label: "Intel" },
  { id: "integrity", label: "Integrity" },
  { id: "about", label: "About" },
];

export default function App() {
  const { state, dismissToast, dismissAlert } = useAegisSocket();
  const { toast, alert } = state;
  const [tab, setTab] = useState<Tab>("live");
  const [vaultKey, setVaultKey] = useState(0);

  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(dismissToast, 6000);
    return () => window.clearTimeout(t);
  }, [toast, dismissToast]);

  useEffect(() => {
    if (!alert) return;
    const t = window.setTimeout(dismissAlert, 3000);
    return () => window.clearTimeout(t);
  }, [alert, dismissAlert]);

  // Re-verify the audit chain after (re)connecting and shortly after new results arrive.
  // The server answers by pushing AUDIT_STATUS, which updates the badge in every tab/client.
  useEffect(() => {
    if (!state.connected) return;
    const t = window.setTimeout(() => void verifyAudit().catch(() => undefined), 700);
    return () => window.clearTimeout(t);
  }, [state.connected, state.stats.total]);

  return (
    <div className="min-h-screen">
      {alert && (
        <div role="alert" key={alert.id}
          className="aegis-flash fixed bottom-4 left-4 z-50 max-w-sm break-all rounded-lg border border-critical bg-critical px-4 py-3 text-sm font-semibold text-white shadow-xl">
          CRITICAL: {alert.filename}
        </div>
      )}
      <HeaderStatus connected={state.connected} drives={Object.values(state.drives)} audit={state.audit} />
      <nav className="border-b border-line bg-card/60" aria-label="Sections">
        <div className="mx-auto flex max-w-7xl gap-1 px-4">
          {TABS.map((t) => (
            <button key={t.id} type="button" onClick={() => setTab(t.id)} aria-current={tab === t.id ? "page" : undefined}
              className={`border-b-2 px-4 py-2 text-sm ${tab === t.id ? "border-live text-live" : "border-transparent text-slate-400 hover:text-slate-200"}`}>
              {t.label}
            </button>
          ))}
        </div>
      </nav>
      <main className="mx-auto max-w-7xl space-y-4 px-4 py-4">
        {tab === "live" && (
          <>
            <ThreatCounters stats={state.stats} />
            <div className="grid gap-4 lg:grid-cols-3">
              <EntropyChart files={state.files} />
              <RiskMatrix files={state.files} />
              <ScanQueueFeed lines={state.feed} />
            </div>
            <ThreatLogTable files={state.files} onVaultChange={() => setVaultKey((k) => k + 1)} />
          </>
        )}
        {tab === "intel" && <IntelPanel />}
        {tab === "about" && <AboutPanel />}
        {tab === "integrity" && (
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="space-y-4">
              <AuditChainBadge audit={state.audit} />
              <VaultPanel refreshKey={vaultKey} />
            </div>
            <ReportPanel files={state.files} />
          </div>
        )}
      </main>
      {toast && (
        <div role="status" key={toast.id} onClick={dismissToast}
          className="fixed bottom-4 right-4 z-50 max-w-sm cursor-pointer rounded-lg border border-live/50 bg-card px-4 py-3 text-sm text-slate-100 shadow-xl">
          {toast.text}
        </div>
      )}
    </div>
  );
}

"use client";

import { useCallback, useEffect, useState } from "react";

type Run = {
  run_id: string;
  model: string;
  spent_microusd: number;
  calls: number;
  cache_hits: number;
  steps: number;
  last_seen_millis: number;
  killed: boolean;
};
type Summary = { runs: number; calls: number; spent_microusd: number };
type Bucket = { t: number; cost_microusd: number; calls: number; blocked: number };
type Alert = {
  run_id: string;
  spent_microusd: number;
  budget_micros: number;
  fraction: number;
  killed: boolean;
};

const usd = (micro: number) => "$" + (micro / 1e6).toFixed(2);

function heatClass(frac: number, killed: boolean): "mint" | "amber" | "ember" {
  if (killed) return "mint";
  if (frac >= 1) return "ember";
  if (frac >= 0.8) return "amber";
  return "mint";
}

function planeHost(base: string): string {
  try {
    return new URL(base).host;
  } catch {
    return "plane";
  }
}

function Sparkline({ buckets }: { buckets: Bucket[] }) {
  const vals = buckets.map((b) => b.cost_microusd);
  if (vals.length < 2) return null;
  const max = Math.max(1, ...vals);
  const W = 600;
  const H = 100;
  const pts = vals
    .map((v, i) => {
      const x = (i / (vals.length - 1)) * W;
      const y = H - (v / max) * (H - 10) - 5;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const lastX = W;
  const lastY = H - (vals[vals.length - 1] / max) * (H - 10) - 5;
  return (
    <svg className="spark" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
      <polygon points={`0,${H} ${pts} ${W},${H}`} fill="rgba(244,178,62,0.22)" />
      <polyline points={pts} fill="none" stroke="#f4b23e" strokeWidth="2.5" vectorEffect="non-scaling-stroke" />
      <circle cx={lastX} cy={lastY} r="3.5" fill="#ff574b" />
    </svg>
  );
}

export default function Page() {
  const [base, setBase] = useState("");
  const [key, setKey] = useState("");
  const [connected, setConnected] = useState(false);
  const [runs, setRuns] = useState<Run[]>([]);
  const [summary, setSummary] = useState<Summary>({ runs: 0, calls: 0, spent_microusd: 0 });
  const [budgets, setBudgets] = useState<Record<string, number>>({});
  const [series, setSeries] = useState<Bucket[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [status, setStatus] = useState("");
  const [armed, setArmed] = useState<string | null>(null);

  useEffect(() => {
    // URL params (?base=&key=) let you connect via a shareable link; they take
    // precedence over the last-used values persisted in localStorage.
    const q = new URLSearchParams(window.location.search);
    const b = q.get("base") || localStorage.getItem("tf_base") || "http://localhost:8080";
    const k = q.get("key") || localStorage.getItem("tf_key") || "";
    setBase(b);
    setKey(k);
    if (k) {
      localStorage.setItem("tf_base", b);
      localStorage.setItem("tf_key", k);
      setConnected(true);
    }
  }, []);

  const api = useCallback(
    async (path: string, init?: RequestInit) => {
      const r = await fetch(base.replace(/\/$/, "") + path, {
        ...init,
        headers: { Authorization: "Bearer " + key, ...(init?.headers || {}) },
      });
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r;
    },
    [base, key],
  );

  const refresh = useCallback(async () => {
    if (!connected || !key) return;
    try {
      const [runsRes, sumRes, budRes, serRes, alertRes] = await Promise.all([
        api("/v1/runs"),
        api("/v1/summary"),
        api("/v1/budgets"),
        api("/v1/series?window=15m&step=60s"),
        api("/v1/alerts"),
      ]);
      const rs: Run[] = await runsRes.json();
      const bud: Record<string, number> = await budRes.json();
      rs.sort((a, b) => {
        const fa = bud[a.run_id] ? a.spent_microusd / bud[a.run_id] : 0;
        const fb = bud[b.run_id] ? b.spent_microusd / bud[b.run_id] : 0;
        return fb - fa || b.spent_microusd - a.spent_microusd;
      });
      setRuns(rs);
      setBudgets(bud);
      setSummary(await sumRes.json());
      setSeries(await serRes.json());
      setAlerts(await alertRes.json());
      setStatus("live");
    } catch (e) {
      setStatus("error: " + (e as Error).message);
    }
  }, [api, connected, key]);

  useEffect(() => {
    if (!connected) return;
    refresh();
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [connected, refresh]);

  const connect = () => {
    localStorage.setItem("tf_base", base);
    localStorage.setItem("tf_key", key);
    setConnected(true);
  };
  const disconnect = () => {
    localStorage.removeItem("tf_key");
    setConnected(false);
  };

  const kill = async (run: string) => {
    if (armed !== run) {
      setArmed(run);
      setTimeout(() => setArmed((a) => (a === run ? null : a)), 2500);
      return;
    }
    setArmed(null);
    try {
      await api(`/v1/runs/${encodeURIComponent(run)}/kill`, { method: "POST" });
      refresh();
    } catch (e) {
      setStatus("kill failed: " + (e as Error).message);
    }
  };

  const setBudget = async (run: string) => {
    const v = prompt(`Set budget for run '${run}' (USD):`);
    if (v === null) return;
    const n = parseFloat(v);
    if (isNaN(n)) return;
    try {
      await api(`/v1/runs/${encodeURIComponent(run)}/budget`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ budget_usd: n }),
      });
      refresh();
    } catch (e) {
      setStatus("set budget failed: " + (e as Error).message);
    }
  };

  const caps = Object.values(budgets).reduce((a, b) => a + b, 0);
  const fleetFrac = caps > 0 ? summary.spent_microusd / caps : 0;
  const lastBurn = [...series].reverse().find((b) => b.cost_microusd > 0);
  const fleetRate = lastBurn ? lastBurn.cost_microusd / 1e6 : 0;
  const maxSpend = Math.max(1, ...runs.map((r) => r.spent_microusd));
  const activeRuns = runs.filter((r) => !r.killed).length;
  const killedRuns = runs.filter((r) => r.killed).length;

  const brand = (
    <div className="brand">
      <svg width="30" height="30" viewBox="0 0 34 34" fill="none" aria-hidden>
        <rect x="1" y="1" width="32" height="32" rx="9" fill="url(#g)" />
        <g transform="translate(17 17) scale(0.92) translate(-11 -12)">
          <path d="M13 2 4 14h6l-1 8 9-12h-6z" fill="none" stroke="#0A0E13"
            strokeWidth="2.4" strokeLinejoin="round" strokeLinecap="round" />
        </g>
        <defs>
          <linearGradient id="g" x1="2" y1="2" x2="32" y2="32" gradientUnits="userSpaceOnUse">
            <stop stopColor="#F6B740" />
            <stop offset="1" stopColor="#FF574B" />
          </linearGradient>
        </defs>
      </svg>
      <div className="w">
        TokenFuse <span>Cloud</span>
      </div>
      <div className="tagm">enforcement, not observability</div>
    </div>
  );

  return (
    <div className="shell">
      <header className="topbar">
        {brand}
        {connected && (
          <div className="conn">
            <span className="chip">
              <span className="k" />
              plane <b>{planeHost(base)}</b> ·{" "}
              <span className={status.startsWith("error") ? "err" : "live"}>
                {status.startsWith("error") ? status : "live · 3s"}
              </span>
            </span>
            <button className="mini" onClick={disconnect}>
              Disconnect
            </button>
          </div>
        )}
      </header>

      {!connected ? (
        <div className="card connect-panel">
          <h2>Connect a control plane</h2>
          <p className="sub">Point the dashboard at a TokenFuse Cloud plane with an org key.</p>
          <div className="row">
            <div>
              <div className="lbl">Plane URL</div>
              <input
                className="field"
                style={{ width: "100%", marginTop: 6 }}
                value={base}
                onChange={(e) => setBase(e.target.value)}
                placeholder="https://…"
              />
            </div>
            <div>
              <div className="lbl">Org key</div>
              <input
                className="field"
                style={{ width: "100%", marginTop: 6 }}
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder="devkey"
              />
            </div>
            <button className="iris" onClick={connect} style={{ marginTop: 4 }}>
              Connect
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="ammeter">
            <span className="lab">Fleet draw</span>
            <div className={"fuse " + heatClass(fleetFrac, false)}>
              <i style={{ width: `${Math.min(100, fleetFrac * 100)}%` }} />
            </div>
            <span className="rd">
              spending <b>{usd(summary.spent_microusd)}</b> of <b>{usd(caps)}</b> caps ·{" "}
              <b style={{ color: "var(--amber)" }}>{Math.round(fleetFrac * 100)}%</b>
            </span>
          </div>

          <div className="heroband">
            <div className="card hero">
              <div className="cap">Fleet burn rate · all gateways</div>
              <div className="rate">
                <span className="v">{fleetRate.toFixed(2)}</span>
                <span className="u">$/min</span>
                <span className="spent">spent {usd(summary.spent_microusd)}</span>
              </div>
              <Sparkline buckets={series} />
              {caps > 0 && (
                <>
                  <div className={"fuse " + heatClass(fleetFrac, false)}>
                    <i style={{ width: `${Math.min(100, fleetFrac * 100)}%` }} />
                  </div>
                  <div className="agl">
                    <span>
                      spent today <b>{usd(summary.spent_microusd)}</b>
                    </span>
                    <span>
                      caps <b>{usd(caps)}</b> · {Math.round(fleetFrac * 100)}%
                    </span>
                  </div>
                </>
              )}
            </div>
            <div className="tiles">
              <div className="card tile">
                <div className="k">Active runs</div>
                <div className="n">{activeRuns}</div>
                <div className="s">{summary.calls} calls</div>
              </div>
              <div className="card tile">
                <div className="k">Spent today</div>
                <div className="n">{usd(summary.spent_microusd)}</div>
                <div className="s">reserve → settle</div>
              </div>
              <div className="card tile alert">
                <div className="k">Alerts</div>
                <div className="n">{alerts.length}</div>
                <div className="s">≥ 80% of cap</div>
              </div>
              <div className="card tile killed">
                <div className="k">Killed</div>
                <div className="n">{killedRuns}</div>
                <div className="s">this org</div>
              </div>
            </div>
          </div>

          <div className="main">
            <div className="card">
              <div className="sechead">
                <div className="t">Runs</div>
                <div className="r">sorted · burn</div>
              </div>
              <div className="tablewrap">
                <table>
                  <thead>
                    <tr>
                      <th>Run</th>
                      <th>Model</th>
                      <th>Spent / cap</th>
                      <th className="num">Calls</th>
                      <th className="num">Steps</th>
                      <th>Status</th>
                      <th className="num">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map((r) => {
                      const budget = budgets[r.run_id] || 0;
                      const frac = budget > 0 ? r.spent_microusd / budget : 0;
                      const heat = heatClass(frac, r.killed);
                      const over = !r.killed && budget > 0 && frac >= 1;
                      return (
                        <tr key={r.run_id} className={over ? "over" : r.killed ? "killedrow" : ""}>
                          <td>
                            <span className="rid">{r.run_id}</span>
                          </td>
                          <td>
                            <span className="rmodel">{r.model || "—"}</span>
                          </td>
                          <td className="spentcell">
                            {budget > 0 ? (
                              <>
                                <div className="nrow">
                                  <b style={over ? { color: "var(--ember)" } : undefined}>{usd(r.spent_microusd)}</b>
                                  <span style={{ color: "var(--dim)" }}>{usd(budget)}</span>
                                </div>
                                <div className={"fuse " + heat}>
                                  <i style={{ width: `${Math.min(100, frac * 100)}%` }} />
                                </div>
                              </>
                            ) : (
                              <>
                                <div className="nrow">
                                  <b>{usd(r.spent_microusd)}</b>
                                </div>
                                <div className="nocap">no cap set</div>
                              </>
                            )}
                          </td>
                          <td className="num">{r.calls}</td>
                          <td className="num">{r.steps}</td>
                          <td>
                            {r.killed ? (
                              <span className="pill dead">killed</span>
                            ) : budget > 0 && frac >= 1 ? (
                              <span className="pill crit">over cap</span>
                            ) : budget > 0 && frac >= 0.8 ? (
                              <span className="pill near">near cap</span>
                            ) : (
                              <span className="pill live">live</span>
                            )}
                          </td>
                          <td>
                            <div className="acts">
                              <button className="mini" onClick={() => setBudget(r.run_id)}>
                                Budget
                              </button>
                              {r.killed ? (
                                <span className="pill dead">402 killed</span>
                              ) : (
                                <button
                                  className={"mini kill" + (armed === r.run_id ? " armed" : "")}
                                  onClick={() => kill(r.run_id)}
                                >
                                  {armed === r.run_id ? "Confirm" : "Kill"}
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {runs.length === 0 && (
                <div className="empty">No runs yet — send traffic through a gateway.</div>
              )}
            </div>

            <div className="rail">
              <div className="card">
                <div className="sechead">
                  <div className="t">Alerts</div>
                  <div className="r">≥ 80% of cap</div>
                </div>
                {alerts.length === 0 ? (
                  <div className="empty" style={{ padding: "28px 20px" }}>
                    Nothing near cap.
                  </div>
                ) : (
                  alerts
                    .sort((a, b) => b.fraction - a.fraction)
                    .map((a) => (
                      <div className="arow" key={a.run_id}>
                        <span className={"d " + (a.fraction >= 1 ? "crit" : "near")} />
                        <div className="tx">
                          <div className="m">
                            Run <span className="id">{a.run_id}</span> {a.fraction >= 1 ? "over cap" : "near cap"}
                          </div>
                          <div className="s">
                            {usd(a.spent_microusd)} / {usd(a.budget_micros)}
                          </div>
                        </div>
                        <span className="pct" style={{ color: a.fraction >= 1 ? "var(--ember)" : "var(--amber)" }}>
                          {Math.round(a.fraction * 100)}%
                        </span>
                      </div>
                    ))
                )}
              </div>

              <div className="card">
                <div className="sechead">
                  <div className="t">Spend by run</div>
                  <div className="r">today</div>
                </div>
                <div className="barchart">
                  {runs.slice(0, 6).map((r) => {
                    const budget = budgets[r.run_id] || 0;
                    const frac = budget > 0 ? r.spent_microusd / budget : 0;
                    return (
                      <div className="bc" key={r.run_id}>
                        <span className="id">{r.run_id}</span>
                        <div className={"fuse " + heatClass(frac, r.killed)}>
                          <i style={{ width: `${(r.spent_microusd / maxSpend) * 100}%` }} />
                        </div>
                        <span className="amt">{usd(r.spent_microusd)}</span>
                      </div>
                    );
                  })}
                  {runs.length === 0 && <div className="empty">—</div>}
                </div>
              </div>
            </div>
          </div>
        </>
      )}

      <footer className="foot">
        <span>
          <b>One identity</b> — the fuse, matching the iOS app
        </span>
        <span>
          <b>Live</b> · burn rate + alerts refresh every 3s
        </span>
        <span>
          <b>Kill</b> — click twice to confirm; enforced across every gateway
        </span>
      </footer>
    </div>
  );
}

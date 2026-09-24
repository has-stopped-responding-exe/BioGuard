import React, { useState, useEffect, useRef } from "react";
import { createRoot } from "react-dom/client";
import {
  Shield,
  ShieldCheck,
  Fingerprint,
  LayoutDashboard,
  TriangleAlert,
  Activity,
  Users,
  ScrollText,
  FlaskConical,
  Radar,
  ArrowUpRight,
  ArrowRight,
  ChevronRight,
  Search,
  RefreshCw,
  X,
  Check,
  LockKeyhole,
  UnlockKeyhole,
  Plus,
  LogOut,
  Menu,
  CircleHelp,
  Globe,
  Monitor,
  Clock,
  Play,
  CheckCircle2,
  KeyRound,
  FileText,
  ExternalLink,
} from "lucide-react";
import "./styles.css";

async function api(path, method = "GET", body) {
  const response = await fetch("/api" + path, {
    method,
    credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response
    .json()
    .catch(() => ({ detail: "The server returned an invalid response." }));
  if (!response.ok) {
    const e = new Error(
      Array.isArray(data.detail)
        ? data.detail.map((x) => x.msg).join("; ")
        : data.detail || "Request failed",
    );
    e.status = response.status;
    throw e;
  }
  return data;
}
const date = (t) =>
  new Date(t).toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
const time = (t) =>
  new Date(t).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
const shortId = (prefix, id) => `${prefix}-${String(id).padStart(4, "0")}`;
function Badge({ value }) {
  return (
    <span className={"badge " + value}>
      <span className="badge-dot" />
      {value.replaceAll("_", " ")}
    </span>
  );
}
function Empty({ children = "No records match your filters." }) {
  return (
    <div className="empty">
      <ShieldCheck size={27} />
      <strong>{children}</strong>
      <span>New activity will appear here as events are recorded.</span>
    </div>
  );
}
function Modal({ title, children, close, wide = false }) {
  const ref = useRef(null);
  useEffect(() => {
    const el = ref.current;
    el.showModal();
    return () => el.close();
  }, []);
  return (
    <dialog
      ref={ref}
      aria-label={title}
      className={wide ? "modal wide" : "modal"}
      onCancel={close}
      onClick={(e) => {
        if (e.target === e.currentTarget) close();
      }}
    >
      <div className="modal-head">
        <div>
          <span className="eyebrow">BIOGUARD / OPERATIONS</span>
          <h2>{title}</h2>
        </div>
        <button
          className="icon-button"
          aria-label="Close dialog"
          onClick={close}
        >
          <X size={20} />
        </button>
      </div>
      {children}
    </dialog>
  );
}
const nav = [
  { name: "Overview", icon: LayoutDashboard },
  { name: "Alerts", icon: TriangleAlert },
  { name: "Authentication events", icon: Activity },
  { name: "Accounts & privacy", icon: Users },
  { name: "Audit log", icon: ScrollText },
];
const scenarios = [
  {
    kind: "normal",
    title: "Normal login",
    text: "A successful match on a known device.",
    icon: ShieldCheck,
    color: "green",
  },
  {
    kind: "failures",
    title: "Repeated failures",
    text: "Five failed attempts. One detection.",
    icon: KeyRound,
    color: "amber",
  },
  {
    kind: "suspicious",
    title: "Suspicious success",
    text: "Failed attempts followed by a new-device login.",
    icon: Radar,
    color: "red",
  },
  {
    kind: "unauthorized",
    title: "Unauthorized access",
    text: "An analyst attempts to read a template.",
    icon: LockKeyhole,
    color: "purple",
  },
];

function App() {
  const [liveState, setLiveState] = useState("Connecting");
  const [streamEpoch, setStreamEpoch] = useState(0);
  const activeInvestigation = useRef(null);
  const [role, setRole] = useState(null),
    [ready, setReady] = useState(false),
    [data, setData] = useState(null),
    [page, setPage] = useState("Overview");
  const [error, setError] = useState(""),
    [toast, setToast] = useState(""),
    [busy, setBusy] = useState(false),
    [modal, setModal] = useState(null),
    [invest, setInvest] = useState(null),
    [mobile, setMobile] = useState(false);
  activeInvestigation.current =
    modal === "investigation" ? invest?.alert.id : null;
  const [search, setSearch] = useState(""),
    [severity, setSeverity] = useState("all"),
    [status, setStatus] = useState("all"),
    [range, setRange] = useState("24"),
    [eventResult, setEventResult] = useState("all");
  async function refresh() {
    try {
      const d = await api("/snapshot");
      setData(d);
      return d;
    } catch (e) {
      if (e.status === 401) {
        setRole(null);
        setData(null);
      }
      throw e;
    }
  }
  useEffect(() => {
    api("/session")
      .then((s) => {
        setRole(s.role);
        return refresh();
      })
      .catch((e) => {
        if (e.status !== 401) setError(e.message);
      })
      .finally(() => setReady(true));
  }, []);
  useEffect(() => {
    if (!role) return;
    let disposed = false,
      running = false,
      pending = false;
    const source = new EventSource("/api/stream");
    setLiveState("Connecting");
    async function synchronize() {
      pending = true;
      if (running) return;
      running = true;
      try {
        while (pending && !disposed) {
          pending = false;
          const next = await api("/snapshot");
          if (disposed) return;
          setData(next);
          const id = activeInvestigation.current;
          if (id) {
            const detail = await api("/alerts/" + id);
            if (!disposed && activeInvestigation.current === id)
              setInvest(detail);
          }
        }
        if (!disposed) setLiveState("Live");
      } catch (e) {
        if (!disposed) {
          setLiveState("Reconnecting");
          if (e.status === 401) {
            source.close();
            setRole(null);
            setData(null);
          } else {
            source.close();
            retry = setTimeout(connectAgain, 2000);
          }
        }
      } finally {
        running = false;
      }
    }
    let retry;
    function connectAgain() {
      if (!disposed) setStreamEpoch((x) => x + 1);
    }
    source.addEventListener("ready", synchronize);
    source.addEventListener("change", synchronize);
    source.addEventListener("expired", () => {
      source.close();
      setRole(null);
      setData(null);
      setModal(null);
    });
    source.onerror = () => {
      if (!disposed) setLiveState("Reconnecting");
      if (!disposed && source.readyState === EventSource.CLOSED) {
        clearTimeout(retry);
        retry = setTimeout(connectAgain, 2000);
      }
      api('/session').catch(e => {
        if (!disposed && e.status === 401) {
          source.close(); setRole(null); setData(null); setModal(null);
        }
      });
    };
    return () => {
      disposed = true;
      source.close();
      clearTimeout(retry);
    };
  }, [role, streamEpoch]);
  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(""), 5500);
    return () => clearTimeout(id);
  }, [toast]);
  function go(p) {
    setPage(p);
    setSearch("");
    setStatus("all");
    setSeverity("all");
    setMobile(false);
  }
  async function run(fn, message) {
    setBusy(true);
    setError("");
    try {
      const out = await fn();
      await refresh();
      if (message) setToast(message);
      return out;
    } catch (e) {
      setError(e.message);
      try {
        await refresh();
      } catch {}
      return null;
    } finally {
      setBusy(false);
    }
  }
  async function signIn(r) {
    setBusy(true);
    try {
      await api("/session", "POST", { role: r });
      setRole(r);
      await refresh();
      setError("");
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function openAlert(id) {
    setBusy(true);
    try {
      setInvest(await api("/alerts/" + id));
      setModal("investigation");
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function demo(kind) {
    const result = await run(
      () => api("/scenarios", "POST", { kind }),
      "Scenario recorded. Events and detections are ready.",
    );
    if (result?.alert_ids.length) {
      await openAlert(
        kind === "suspicious" ? result.alert_ids[1] : result.alert_ids[0],
      );
    } else if (result) {
      go("Authentication events");
    }
  }
  async function response(path, method, body, message) {
    const r = await run(() => api(path, method, body), message);
    if (r && invest) setInvest(await api("/alerts/" + invest.alert.id));
    return r;
  }
  const isAdmin = role === "admin";
  const cutoff = Date.now() - Number(range) * 3600000;
  const match = (x) =>
    JSON.stringify(x).toLowerCase().includes(search.toLowerCase());
  const filteredAlerts = (data?.alerts || []).filter(
    (a) =>
      match(a) &&
      (severity === "all" || a.severity === severity) &&
      (status === "all" || a.status === status) &&
      new Date(a.created_at).getTime() >= cutoff,
  );
  const filteredEvents = (data?.events || []).filter(
    (e) =>
      match(e) &&
      (eventResult === "all" || e.result === eventResult) &&
      new Date(e.timestamp).getTime() >= cutoff,
  );

  if (!ready)
    return (
      <div className="loading-screen">
        <Fingerprint size={48} />
        <h2>Connecting to BioGuard…</h2>
      </div>
    );
  if (!role)
    return (
      <main className="login">
        <div className="login-brand">
          <Fingerprint size={52} />
          <span>BioGuard</span>
        </div>
        <div className="login-card">
          <span className="eyebrow">SECURITY OPERATIONS / LOCAL SANDBOX</span>
          <h1>
            Understand the threat.
            <br />
            <em>Protect the identity.</em>
          </h1>
          <p>
            Investigate synthetic biometric authentication incidents, trace the
            evidence, and put a response into action.
          </p>
          <div className="sandbox-note">
            <ShieldCheck size={22} />
            <span>
              Generated test data only. No fingerprints, face images, or Aadhaar
              information are collected.
            </span>
          </div>
          {error && (
            <div role="alert" className="error">
              {error}
            </div>
          )}
          <button
            disabled={busy}
            className="primary full"
            onClick={() => signIn("admin")}
          >
            Enter as demo admin <ArrowRight size={18} />
          </button>
          <button
            disabled={busy}
            className="secondary full"
            onClick={() => signIn("analyst")}
          >
            Enter as demo analyst
          </button>
          <small>
            Local training access • roles are intentionally selectable.
            <br />
            This is not a production identity service.
          </small>
        </div>
        <span className="login-footer">
          BIOMETRIC AUTHENTICATION THREAT DETECTION SYSTEM
        </span>
      </main>
    );
  return (
    <div className="app">
      <a className="skip" href="#main">
        Skip to content
      </a>
      <aside className={mobile ? "sidebar visible" : "sidebar"}>
        <a
          className="brand"
          href="#"
          onClick={(e) => {
            e.preventDefault();
            go("Overview");
          }}
        >
          <div className="brand-icon">
            <Fingerprint size={28} />
          </div>
          <div>
            BioGuard<small>SECURITY OPERATIONS</small>
          </div>
        </a>
        <div className="workspace">
          <span className="workspace-icon">
            <Shield size={17} />
          </span>
          <div>
            Demo workspace<small>Synthetic environment</small>
          </div>
          <span className="live-dot" />
        </div>
        <div className="nav-label">MONITOR</div>
        <nav>
          {nav.map(({ name, icon: Icon }) => (
            <button
              key={name}
              onClick={() => go(name)}
              className={page === name ? "nav-item active" : "nav-item"}
            >
              <Icon size={18} />
              <span>{name}</span>
              {name === "Alerts" && data?.stats.open_alerts > 0 && (
                <b>{data.stats.open_alerts}</b>
              )}
            </button>
          ))}
        </nav>
        <div className="nav-label second">WORKSPACE</div>
        <nav>
          <button
            className={
              "nav-item " + (page === "Simulation lab" ? "active" : "")
            }
            onClick={() => go("Simulation lab")}
          >
            <FlaskConical size={18} />
            Simulation lab<span className="mini-tag">DEMO</span>
          </button>
          <button
            className={
              "nav-item " + (page === "Threat intelligence" ? "active" : "")
            }
            onClick={() => go("Threat intelligence")}
          >
            <Globe size={18} />
            Threat intelligence
          </button>
          <button
            className={
              "nav-item " + (page === "Detection rules" ? "active" : "")
            }
            onClick={() => go("Detection rules")}
          >
            <Radar size={18} />
            Detection rules
          </button>
        </nav>
        <div className="sidebar-bottom">
          <div className="privacy-mark">
            <ShieldCheck size={18} />
            <span>
              Privacy by design<small>100% synthetic biometric data</small>
            </span>
          </div>
          <button
            className="help-button"
            onClick={() => setModal("walkthrough")}
          >
            <CircleHelp size={17} /> Interview walkthrough{" "}
            <ArrowUpRight size={16} />
          </button>
          <div className="profile">
            <div className="avatar">{isAdmin ? "AD" : "AN"}</div>
            <div>
              Demo {role}
              <small>{isAdmin ? "Administrator" : "Read & simulate"}</small>
            </div>
            <button
              className="icon-button"
              title="Sign out"
              aria-label="Sign out"
              onClick={async () => {
                await api("/session", "DELETE");
                setRole(null);
                setData(null);
              }}
            >
              <LogOut size={17} />
            </button>
          </div>
        </div>
      </aside>
      <div className="shell">
        <header className="topbar">
          <div className="breadcrumbs">
            <button
              className="icon-button mobile-toggle"
              aria-label="Toggle navigation"
              onClick={() => setMobile(!mobile)}
            >
              <Menu size={21} />
            </button>
            <span>Workspace</span>
            <ChevronRight size={14} />
            <strong>{page}</strong>
          </div>
          <div className="top-right">
            <span className="environment">
              <span className="live-dot" />
              Sandbox · {liveState}
            </span>
            <span className="top-divider" />
            <span className="role-tag">{role}</span>
            <div className="avatar small">{isAdmin ? "AD" : "AN"}</div>
          </div>
        </header>
        <main id="main">
          <div className="page-heading">
            <div>
              <div className="eyebrow">IDENTITY THREAT MONITORING</div>
              <h1>{page === "Overview" ? "Security overview" : page}</h1>
              <p>
                {
                  {
                    Overview:
                      "Visibility into every authentication. Confidence in every response.",
                    Alerts:
                      "Triage detections, review the evidence, and contain account risk.",
                    "Authentication events":
                      "A traceable record of every synthetic authentication and template request.",
                    "Accounts & privacy":
                      "Manage test identities, explicit consent, and synthetic templates.",
                    "Audit log":
                      "An append-only record of investigation and administrative actions.",
                    "Simulation lab":
                      "Create real events. Trigger real rules. Practice a complete response.",
                    "Threat intelligence":
                      "Optional public-IP context from Shodan, listed in OSINT Framework.",
                    "Detection rules":
                      "Transparent, deterministic rules evaluated by the backend.",
                  }[page]
                }
              </p>
            </div>
            <div className="heading-actions">
              <button
                className="secondary icon-button"
                title="Refresh data"
                aria-label="Refresh data"
                disabled={busy}
                onClick={() =>
                  run(async () => ({ ok: true }), "Dashboard refreshed.")
                }
              >
                <RefreshCw size={17} />
              </button>
              {page === "Accounts & privacy" ? (
                <button
                  className="primary"
                  disabled={!isAdmin || busy}
                  onClick={() => setModal("enroll")}
                >
                  <Plus size={17} />
                  Enroll test account
                </button>
              ) : (
                <button
                  className="primary"
                  onClick={() => setModal("simulate")}
                  disabled={busy}
                >
                  <Play size={16} />
                  Simulate login
                </button>
              )}
            </div>
          </div>
          {error && (
            <div className="error" role="alert">
              <TriangleAlert size={18} />
              <span>{error}</span>
              <button aria-label="Dismiss error" onClick={() => setError("")}>
                <X size={16} />
              </button>
            </div>
          )}
          {!data ? (
            <Empty>Unable to load dashboard. Use refresh to reconnect.</Empty>
          ) : (
            <>
              {page === "Overview" && (
                <>
                  <div className="overview-toolbar">
                    <div className="live-label">
                      <span className="live-dot" />
                      Detection engine active
                      <span className="subtle">4 rules monitoring</span>
                    </div>
                    <span className="subtle" role="status">
                      {liveState === "Live"
                        ? "Live updates · connected"
                        : liveState + "…"}
                    </span>
                  </div>
                  <div className="stats-grid">
                    {[
                      {
                        label: "Open alerts",
                        value: data.stats.open_alerts,
                        icon: TriangleAlert,
                        color: "amber",
                        sub: `${data.stats.severities.critical || 0} critical requiring attention`,
                      },
                      {
                        label: "Authentication events",
                        value: data.stats.total_events,
                        icon: Activity,
                        color: "mint",
                        sub: "All recorded security events",
                      },
                      {
                        label: "Affected accounts",
                        value: data.stats.affected_accounts,
                        icon: Users,
                        color: "purple",
                        sub: "Accounts with open detections",
                      },
                      {
                        label: "Enrolled identities",
                        value: data.users.length,
                        icon: Fingerprint,
                        color: "blue",
                        sub: `${data.users.filter((u) => u.consent).length} with active consent`,
                      },
                    ].map(({ label, value, icon: Icon, color, sub }) => (
                      <section className="stat-card" key={label}>
                        <div className="stat-top">
                          <span>{label}</span>
                          <Icon className={color} size={18} />
                        </div>
                        <div className="stat-value">
                          {value.toLocaleString()}
                          <span className={"stat-indicator " + color}>
                            <span />
                            {liveState === 'Live' ? 'LIVE' : 'OFFLINE'}
                          </span>
                        </div>
                        <small>{sub}</small>
                      </section>
                    ))}
                  </div>
                  <div className="charts-grid">
                    <section className="panel activity-panel">
                      <div className="panel-heading">
                        <div>
                          <h2>Authentication activity</h2>
                          <p>Event volume over the last 24 hours</p>
                        </div>
                        <div className="legend">
                          <span>
                            <i className="mint-bg" />
                            All events
                          </span>
                          <span>
                            <i className="red-bg" />
                            Failed / denied
                          </span>
                        </div>
                      </div>
                      <ActivityChart activity={data.activity} />
                    </section>
                    <section className="panel posture">
                      <div className="panel-heading">
                        <h2>Alert severity</h2>
                        <span className="subtle">Open alerts</span>
                      </div>
                      <div className="severity-body">
                        <div
                          className="donut"
                          style={{
                            "--critical": `${(100 * (data.stats.severities.critical || 0)) / Math.max(1, data.stats.open_alerts)}%`,
                            "--high": `${(100 * ((data.stats.severities.critical || 0) + (data.stats.severities.high || 0))) / Math.max(1, data.stats.open_alerts)}%`,
                          }}
                        >
                          <div>
                            <strong>{data.stats.open_alerts}</strong>
                            <small>OPEN ALERTS</small>
                          </div>
                        </div>
                        <div className="severity-key">
                          {["critical", "high", "medium"].map((s) => (
                            <button
                              key={s}
                              onClick={() => {
                                go("Alerts");
                                setSeverity(s);
                                setStatus("open");
                              }}
                            >
                              <span className={"severity-dot " + s} />
                              <span>{s}</span>
                              <strong>{data.stats.severities[s] || 0}</strong>
                            </button>
                          ))}
                        </div>
                      </div>
                      <div className="panel-foot">
                        <Shield size={14} /> Every alert is backed by event
                        evidence.
                      </div>
                    </section>
                  </div>
                  <section className="panel">
                    <div className="panel-heading">
                      <div className="inline">
                        <h2>Priority alerts</h2>
                        <span className="count">{data.stats.open_alerts}</span>
                      </div>
                      <button
                        className="text-button"
                        onClick={() => {
                          go("Alerts");
                          setStatus("open");
                        }}
                      >
                        View all alerts <ArrowRight size={15} />
                      </button>
                    </div>
                    <AlertTable
                      alerts={data.alerts
                        .filter((a) => a.status === "open")
                        .sort(
                          (a, b) =>
                            ({ critical: 0, high: 1, medium: 2 })[a.severity] -
                            { critical: 0, high: 1, medium: 2 }[b.severity],
                        )
                        .slice(0, 4)}
                      open={openAlert}
                    />
                  </section>
                  <div className="section-heading">
                    <div>
                      <h2>Put your defenses to the test</h2>
                      <p>Launch a scenario and follow the evidence.</p>
                    </div>
                    <span className="outline-tag">
                      <FlaskConical size={13} /> SYNTHETIC DATA ONLY
                    </span>
                  </div>
                  <div className="scenario-grid">
                    {scenarios.map((s) => (
                      <Scenario
                        key={s.kind}
                        scenario={s}
                        run={demo}
                        disabled={busy || !isAdmin}
                      />
                    ))}
                  </div>
                </>
              )}
              {page === "Alerts" && (
                <section className="panel">
                  <Filters
                    search={search}
                    setSearch={setSearch}
                    range={range}
                    setRange={setRange}
                  >
                    <select
                      aria-label="Severity"
                      value={severity}
                      onChange={(e) => setSeverity(e.target.value)}
                    >
                      <option value="all">All severities</option>
                      {["critical", "high", "medium"].map((v) => (
                        <option key={v}>{v}</option>
                      ))}
                    </select>
                    <select
                      aria-label="Alert status"
                      value={status}
                      onChange={(e) => setStatus(e.target.value)}
                    >
                      <option value="all">All statuses</option>
                      <option value="open">Open</option>
                      <option value="acknowledged">Acknowledged</option>
                    </select>
                  </Filters>
                  <AlertTable alerts={filteredAlerts} open={openAlert} />
                  <div className="panel-foot">
                    {filteredAlerts.length} results · Latest {data.list_limit}{" "}
                    alerts available
                  </div>
                </section>
              )}
              {page === "Authentication events" && (
                <section className="panel">
                  <Filters {...{ search, setSearch, range, setRange }}>
                    <select
                      aria-label="Event result"
                      value={eventResult}
                      onChange={(e) => setEventResult(e.target.value)}
                    >
                      <option value="all">All results</option>
                      {["success", "failure", "denied"].map((v) => (
                        <option key={v}>{v}</option>
                      ))}
                    </select>
                  </Filters>
                  <EventTable events={filteredEvents} />
                  <div className="panel-foot">
                    {filteredEvents.length} results · Latest {data.list_limit}{" "}
                    events available · Times shown in your local timezone
                  </div>
                </section>
              )}
              {page === "Accounts & privacy" && (
                <>
                  <div className="info-banner">
                    <ShieldCheck size={20} />
                    <span>
                      Consent is explicit and revocable. Template IDs are
                      synthetic references; no biometric samples are stored.
                    </span>
                  </div>
                  <section className="panel">
                    <Filters search={search} setSearch={setSearch} />
                    <div className="table-scroll">
                      <table>
                        <thead>
                          <tr>
                            <th>Test identity</th>
                            <th>Consent</th>
                            <th>Template</th>
                            <th>Account</th>
                            <th>Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {data.users.filter(match).map((u) => (
                            <tr key={u.id}>
                              <td>
                                <div className="identity-cell">
                                  <div className="avatar">
                                    {u.name
                                      .split(" ")
                                      .slice(0, 2)
                                      .map((n) => n[0])
                                      .join("")}
                                  </div>
                                  <div>
                                    <strong>{u.name}</strong>
                                    <small>{u.email}</small>
                                  </div>
                                </div>
                              </td>
                              <td>
                                <Badge
                                  value={u.consent ? "granted" : "withdrawn"}
                                />
                                <small>
                                  {date(u.withdrawn_at || u.consent_at)}
                                </small>
                              </td>
                              <td>
                                <Badge
                                  value={u.has_template ? "present" : "deleted"}
                                />
                              </td>
                              <td>
                                <Badge value={u.locked ? "locked" : "active"} />
                              </td>
                              <td>
                                <button
                                  className="secondary compact"
                                  onClick={() => {
                                    setModal({ type: "account", id: u.id });
                                  }}
                                >
                                  Manage <ChevronRight size={14} />
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {!data.users.filter(match).length && <Empty />}
                  </section>
                </>
              )}
              {page === "Audit log" && (
                <section className="panel">
                  <Filters search={search} setSearch={setSearch} />
                  <AuditTable entries={data.audit.filter(match)} />
                  <div className="panel-foot">
                    Latest {data.list_limit} audit entries · Historical evidence
                    is retained after template deletion
                  </div>
                </section>
              )}
              {page === "Simulation lab" && (
                <>
                  <div className="info-banner">
                    <FlaskConical size={20} />
                    <span>
                      Each scenario creates a fresh test account with consent
                      and a known-device baseline. Scenarios remain repeatable
                      after account locks or consent withdrawal.
                    </span>
                  </div>
                  <div className="scenario-grid lab">
                    {scenarios.map((s) => (
                      <Scenario
                        key={s.kind}
                        scenario={s}
                        run={demo}
                        disabled={busy || !isAdmin}
                      />
                    ))}
                  </div>
                  <section className="panel lab-description">
                    <Fingerprint size={44} />
                    <div>
                      <h2>Build your own authentication event</h2>
                      <p>
                        Choose an enrolled test account, device, documentation
                        IP, and match result. The backend enforces account and
                        consent controls before evaluating detection rules.
                      </p>
                      <button
                        className="primary"
                        onClick={() => setModal("simulate")}
                      >
                        <Play size={16} />
                        Open authentication simulator
                      </button>
                    </div>
                  </section>
                  {!isAdmin && (
                    <p className="subtle">
                      Scenario generation requires admin. Analysts can use the
                      authentication simulator.
                    </p>
                  )}
                </>
              )}
              {page === "Threat intelligence" && (
                <Intelligence run={run} busy={busy} />
              )}
              {page === "Detection rules" && (
                <div className="rules-list">
                  {data.rules.map((r) => (
                    <section className="panel rule-card" key={r.id}>
                      <div className="rule-symbol">
                        <Radar size={25} />
                      </div>
                      <div>
                        <span className="eyebrow">{r.id} · ENABLED</span>
                        <h2>{r.title}</h2>
                        <p>{r.description}</p>
                      </div>
                      <Badge value={r.severity} />
                    </section>
                  ))}
                  <div className="info-banner">
                    <FileText size={19} />
                    <span>
                      All rule evaluation runs in FastAPI. Event evidence and
                      alerts are written in the same SQLite transaction.
                    </span>
                  </div>
                </div>
              )}
            </>
          )}
          <footer>
            <span>
              <ShieldCheck size={13} /> BioGuard · Synthetic biometric security
              lab
            </span>
            <span>
              Local prototype <span className="footer-dot">•</span> No real
              biometric data
            </span>
          </footer>
        </main>
      </div>
      {toast && (
        <div className="toast" role="status">
          <CheckCircle2 size={20} />
          {toast}
          <button
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <X size={16} />
          </button>
        </div>
      )}
      {modal === "simulate" && (
        <Modal title="Simulate authentication" close={() => setModal(null)}>
          <FormError error={error} />
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              const f = new FormData(e.currentTarget);
              const r = await run(
                () =>
                  api("/simulations", "POST", {
                    user_id: Number(f.get("user_id")),
                    device_id: f.get("device_id"),
                    ip: f.get("ip"),
                    result: f.get("result"),
                  }),
                "Authentication event recorded.",
              );
              if (r) setModal(null);
            }}
          >
            <p className="modal-intro">
              Generate a test login. Account locks, withdrawn consent, and
              deleted templates will override a successful match.
            </p>
            <label>
              Test account
              <select name="user_id" required>
                {data?.users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.name}
                    {u.locked ? " · locked" : ""}
                    {!u.consent ? " · consent withdrawn" : ""}
                  </option>
                ))}
              </select>
            </label>
            <div className="form-grid">
              <label>
                Device ID
                <input
                  name="device_id"
                  defaultValue="WS-DEMO"
                  required
                  minLength={2}
                  maxLength={48}
                  pattern="[A-Za-z0-9_\-]+"
                />
              </label>
              <label>
                Synthetic IP address
                <input name="ip" defaultValue="192.0.2.50" required />
              </label>
            </div>
            <small>Use 192.0.2.x, 198.51.100.x, or 203.0.113.x.</small>
            <label>
              Biometric match result
              <select name="result">
                <option value="success">Successful match</option>
                <option value="failure">Failed match</option>
              </select>
            </label>
            <button
              className="primary full"
              disabled={busy || !data?.users.length}
            >
              <Play size={16} />
              {busy ? "Recording…" : "Record authentication"}
            </button>
          </form>
        </Modal>
      )}
      {modal === "enroll" && (
        <Modal title="Enroll a test identity" close={() => setModal(null)}>
          <FormError error={error} />
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              const f = new FormData(e.currentTarget);
              const r = await run(
                () =>
                  api("/users", "POST", {
                    name: f.get("name"),
                    consent: f.get("consent") === "on",
                  }),
                "Test account enrolled with consent.",
              );
              if (r) setModal(null);
            }}
          >
            <p className="modal-intro">
              Use a fictional name. BioGuard generates a .test email and a
              random synthetic template ID automatically.
            </p>
            <label>
              Fictional display name
              <input
                name="name"
                placeholder="e.g. Avery Quinn"
                required
                minLength={2}
                maxLength={60}
                pattern="[A-Za-z][A-Za-z .\-]*"
              />
            </label>
            <label className="checkbox">
              <input type="checkbox" name="consent" required />
              <span>
                I explicitly consent to storing a synthetic template for this
                test account and processing simulated authentication events.
                Consent can be withdrawn at any time.
              </span>
            </label>
            <button disabled={busy} className="primary full">
              <Plus size={17} />
              Create synthetic account
            </button>
          </form>
        </Modal>
      )}
      {modal?.type === "account" && (
        <AccountModal
          user={data.users.find((u) => u.id === modal.id)}
          close={() => setModal(null)}
          response={response}
          busy={busy}
          isAdmin={isAdmin}
          error={error}
        />
      )}
      {modal === "investigation" && invest && (
        <Modal
          wide
          title={`Investigate ${shortId("BG", invest.alert.id)}`}
          close={() => setModal(null)}
        >
          <FormError error={error} />
          <div className="invest-summary">
            <div>
              <div className="inline">
                <Badge value={invest.alert.severity} />
                <Badge value={invest.alert.status} />
                <span className="mono">{invest.alert.rule}</span>
              </div>
              <h3>{invest.alert.title}</h3>
              <p>
                {invest.alert.name} <span>·</span>{" "}
                {date(invest.alert.created_at)}
              </p>
            </div>
            <div className="response-actions">
              <button
                disabled={busy || !isAdmin || invest.alert.status !== "open"}
                className="primary"
                onClick={() =>
                  response(
                    `/alerts/${invest.alert.id}/acknowledge`,
                    "POST",
                    null,
                    "Alert acknowledged.",
                  )
                }
              >
                <Check size={16} />
                Acknowledge
              </button>
              <button
                disabled={busy || !isAdmin}
                className="secondary"
                onClick={() =>
                  response(
                    `/users/${invest.alert.user_id}/lock`,
                    "PATCH",
                    {
                      locked: !data.users.find(
                        (u) => u.id === invest.alert.user_id,
                      )?.locked,
                    },
                    "Account state updated.",
                  )
                }
              >
                <LockKeyhole size={16} />
                {data.users.find((u) => u.id === invest.alert.user_id)?.locked
                  ? "Unlock account"
                  : "Lock account"}
              </button>
            </div>
          </div>
          <div className="rule-explanation">
            <Radar size={18} />
            <span>
              <strong>Why this fired</strong>
              {data.rules.find((r) => r.id === invest.alert.rule)?.description}
            </span>
          </div>
          <h3 className="section-title">
            Supporting evidence{" "}
            <span className="count">{invest.evidence.length} events</span>
          </h3>
          <EventTable events={invest.evidence} compact />
          <h3 className="section-title">Chronological account timeline</h3>
          <div className="timeline">
            {invest.timeline.map((e) => (
              <div className="timeline-event" key={e.id}>
                <span className={"timeline-dot " + e.result} />
                <span className="mono">{time(e.timestamp)}</span>
                <div>
                  <strong>
                    {e.kind === "login" ? "Biometric login" : "Template access"}{" "}
                    · {e.result}
                  </strong>
                  <small>
                    {e.reason} · {e.device_id} · {e.ip}
                  </small>
                </div>
                <span className="event-ref">
                  #{e.id}
                  {invest.evidence.some((v) => v.id === e.id) && (
                    <b>Evidence</b>
                  )}
                </span>
              </div>
            ))}
          </div>
          <div className="invest-bottom">
            <section>
              <h3 className="section-title">Investigation notes</h3>
              {invest.notes.map((n) => (
                <div className="note" key={n.id}>
                  <small>
                    {n.actor} · {date(n.timestamp)}
                  </small>
                  <p>{n.body}</p>
                </div>
              ))}
              {!invest.notes.length && (
                <p className="subtle">
                  No notes yet. Record your assessment and response.
                </p>
              )}
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  const form = e.currentTarget;
                  const r = await response(
                    `/alerts/${invest.alert.id}/notes`,
                    "POST",
                    { body: new FormData(form).get("body") },
                    "Investigation note saved.",
                  );
                  if (r) form.reset();
                }}
              >
                <label>
                  Investigation note
                  <textarea
                    name="body"
                    required
                    maxLength={2000}
                    placeholder="Describe findings, containment, and next steps…"
                    disabled={!isAdmin}
                  />
                </label>
                <button className="secondary" disabled={busy || !isAdmin}>
                  <Plus size={15} />
                  Add note
                </button>
              </form>
            </section>
            <section>
              <h3 className="section-title">Response audit trail</h3>
              <div className="audit-stack">
                {[...invest.audit].reverse().map((a) => (
                  <div key={a.id}>
                    <CheckCircle2 size={15} />
                    <div>
                      <strong>{a.action}</strong>
                      <small>
                        {a.actor} · {date(a.timestamp)}
                      </small>
                      {a.detail && <p>{a.detail}</p>}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </Modal>
      )}
      {modal === "walkthrough" && (
        <Modal title="Your interview walkthrough" close={() => setModal(null)}>
          <ol className="walkthrough">
            <li>
              <strong>Trigger an incident</strong>
              <p>
                Run “Suspicious success” in the simulation lab. Five failures
                and a new-device success create three detections.
              </p>
            </li>
            <li>
              <strong>Follow the evidence</strong>
              <p>
                Inspect the critical alert, rule explanation, event IDs, and
                chronological timeline.
              </p>
            </li>
            <li>
              <strong>Contain and document</strong>
              <p>
                Acknowledge the alert, lock the account, and add an
                investigation note.
              </p>
            </li>
            <li>
              <strong>Prove the response</strong>
              <p>
                Show the audit trail. Simulate another successful match for the
                locked account to demonstrate it is blocked.
              </p>
            </li>
            <li>
              <strong>Explain the privacy boundary</strong>
              <p>
                Withdraw consent or delete a synthetic template in Accounts &
                privacy. Analyst template requests are denied and generate
                alerts.
              </p>
            </li>
          </ol>
          <button
            className="primary full"
            onClick={() => {
              setModal(null);
              go("Simulation lab");
            }}
          >
            Open simulation lab <ArrowRight size={16} />
          </button>
        </Modal>
      )}
    </div>
  );
}

function FormError({ error }) {
  return error ? (
    <div className="error" role="alert">
      {error}
    </div>
  ) : null;
}
function Filters({ search, setSearch, range, setRange, children }) {
  return (
    <div className="filters">
      <div className="search">
        <Search size={17} />
        <input
          aria-label="Search records"
          placeholder="Search accounts, events, or IDs…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>
      {children}
      {range && (
        <select
          aria-label="Time range"
          value={range}
          onChange={(e) => setRange(e.target.value)}
        >
          <option value="1">Last hour</option>
          <option value="24">Last 24 hours</option>
          <option value="168">Last 7 days</option>
          <option value="876000">All time</option>
        </select>
      )}
    </div>
  );
}
function AlertTable({ alerts, open }) {
  return alerts.length ? (
    <div className="table-scroll">
      <table className="alert-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Detection / alert</th>
            <th>Affected account</th>
            <th>Status</th>
            <th>Detected at</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.id}>
              <td>
                <Badge value={a.severity} />
              </td>
              <td>
                <button className="table-link" onClick={() => open(a.id)}>
                  {a.title}
                </button>
                <small className="mono">
                  {shortId("BG", a.id)} <span>·</span> {a.rule}
                </small>
              </td>
              <td>
                <span className="account-name">
                  <span className="tiny-avatar">
                    {a.name
                      .split(" ")
                      .slice(0, 2)
                      .map((n) => n[0])
                      .join("")}
                  </span>
                  {a.name}
                </span>
              </td>
              <td>
                <Badge value={a.status} />
              </td>
              <td className="mono muted">{date(a.created_at)}</td>
              <td>
                <button
                  className="icon-button"
                  aria-label={`Investigate alert ${a.id}`}
                  onClick={() => open(a.id)}
                >
                  <ArrowUpRight size={17} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty>No alerts to display.</Empty>
  );
}
function EventTable({ events, compact = false }) {
  return events.length ? (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Event / time</th>
            {!compact && <th>Account</th>}
            <th>Device / IP</th>
            <th>Result</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td>
                <strong className="mono">{shortId("EVT", e.id)}</strong>
                <small>{date(e.timestamp)}</small>
              </td>
              {!compact && <td>{e.name || `Account #${e.user_id}`}</td>}
              <td>
                <span className="mono">{e.device_id}</span>
                <small className="mono">{e.ip}</small>
              </td>
              <td>
                <Badge value={e.result} />
              </td>
              <td>
                <strong className="event-reason">{e.reason}</strong>
                <small>
                  {e.kind.replace("_", " ")} · {e.actor}
                </small>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty>No events to display.</Empty>
  );
}
function AuditTable({ entries }) {
  return entries.length ? (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Action</th>
            <th>Actor</th>
            <th>Account / alert</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((a) => (
            <tr key={a.id}>
              <td className="mono muted">{date(a.timestamp)}</td>
              <td>
                <strong>{a.action}</strong>
                <small>Audit #{a.id}</small>
              </td>
              <td>{a.actor}</td>
              <td>
                {a.name || "Workspace"}
                <small>{a.alert_id ? shortId("BG", a.alert_id) : "—"}</small>
              </td>
              <td className="audit-detail">{a.detail || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty>No audit entries to display.</Empty>
  );
}
function Scenario({ scenario: s, run, disabled }) {
  const Icon = s.icon;
  return (
    <button
      disabled={disabled}
      className="scenario"
      onClick={() => run(s.kind)}
    >
      <div className="scenario-top">
        <span className={"scenario-icon " + s.color}>
          <Icon size={20} />
        </span>
        <ArrowUpRight size={16} />
      </div>
      <h3>{s.title}</h3>
      <p>{s.text}</p>
      <span className="scenario-run">
        <Play size={12} />
        Run scenario
      </span>
    </button>
  );
}
function ActivityChart({ activity }) {
  const now = new Date();
  now.setMinutes(0, 0, 0);
  const buckets = Array.from({ length: 24 }, (_, i) => {
    const d = new Date(now.getTime() - (23 - i) * 3600000);
    const key = d.toISOString().slice(0, 13);
    const found = activity.find((x) => x.hour === key);
    return {
      label:
        d.toLocaleTimeString(undefined, { hour: "2-digit", hour12: false }) +
        ":00",
      total: found?.total || 0,
      failed: found?.failed || 0,
    };
  });
  const max = Math.max(5, ...buckets.map((b) => b.total));
  return (
    <div className="activity-chart">
      <div className="y-axis">
        <span>{max}</span>
        <span>{Math.round(max / 2)}</span>
        <span>0</span>
      </div>
      <div className="plot">
        <div className="grid-lines">
          <i />
          <i />
          <i />
        </div>
        <div className="bars">
          {buckets.map((b, i) => (
            <div
              key={i}
              className="bar-column"
              title={`${b.label}: ${b.total} events, ${b.failed} failed / denied`}
            >
              <div
                className="bar"
                style={{ height: `${Math.max(1, (b.total / max) * 100)}%` }}
              >
                <div
                  style={{
                    height: `${b.total ? (b.failed / b.total) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>
          ))}
        </div>
        <div className="x-axis">
          {buckets
            .filter((_, i) => i % 4 === 0 || i === 23)
            .map((b, i) => (
              <span key={i}>{b.label}</span>
            ))}
        </div>
      </div>
    </div>
  );
}
function AccountModal({ user: u, close, response, busy, isAdmin, error }) {
  const [template, setTemplate] = useState(null),
    [confirm, setConfirm] = useState(null);
  return (
    <Modal title={u.name} close={close}>
      <FormError error={error} />
      <p className="modal-intro">
        {u.email} · Account #{u.id}
      </p>
      <div className="account-status">
        <Badge value={u.locked ? "locked" : "active"} />
        <Badge value={u.consent ? "granted" : "withdrawn"} />
        <Badge value={u.has_template ? "present" : "deleted"} />
      </div>
      <div className="account-control">
        <div>
          <strong>Account access</strong>
          <p>Locked accounts cannot authenticate.</p>
        </div>
        <button
          className="secondary"
          disabled={busy || !isAdmin}
          onClick={() =>
            response(
              `/users/${u.id}/lock`,
              "PATCH",
              { locked: !u.locked },
              "Account state updated.",
            )
          }
        >
          {u.locked ? <UnlockKeyhole size={16} /> : <LockKeyhole size={16} />}{" "}
          {u.locked ? "Unlock" : "Lock"}
        </button>
      </div>
      <div className="account-control">
        <div>
          <strong>Explicit consent</strong>
          <p>
            {u.consent ? "Granted" : "Withdrawn"} ·{" "}
            {date(u.withdrawn_at || u.consent_at)}
          </p>
        </div>
        <button
          disabled={busy || !isAdmin || !u.consent}
          className="secondary"
          onClick={() => setConfirm("withdraw")}
        >
          Withdraw
        </button>
      </div>
      <div className="account-control">
        <div>
          <strong>Synthetic template</strong>
          <p>Admin-only access, subject to consent.</p>
        </div>
        <button
          className="secondary"
          disabled={busy}
          onClick={async () => {
            const r = await response(
              `/users/${u.id}/template-access`,
              "POST",
              null,
              "Template access recorded.",
            );
            setTemplate(r?.template_id || null);
          }}
        >
          Request access
        </button>
      </div>
      {template && u.consent && u.has_template && (
        <code className="template-id">{template}</code>
      )}
      <button
        className="danger full"
        disabled={busy || !isAdmin || !u.has_template}
        onClick={() => setConfirm("delete")}
      >
        Delete synthetic template
      </button>
      {confirm && (
        <div className="confirm-box">
          <strong>
            {confirm === "delete"
              ? "Permanently delete this synthetic template?"
              : "Withdraw consent for this account?"}
          </strong>
          <p>
            Authentication will be blocked. Historical events and audit records
            remain available. This action cannot be undone for this test
            account.
          </p>
          <div className="inline">
            <button
              className="danger"
              disabled={busy}
              onClick={async () => {
                const r = await response(
                  `/users/${u.id}/${confirm === "delete" ? "template" : "withdraw"}`,
                  confirm === "delete" ? "DELETE" : "POST",
                  null,
                  "Privacy action recorded.",
                );
                if (r) {
                  setConfirm(null);
                  setTemplate(null);
                }
              }}
            >
              Confirm {confirm === "delete" ? "deletion" : "withdrawal"}
            </button>
            <button className="secondary" onClick={() => setConfirm(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}
      {!isAdmin && (
        <p className="subtle">
          Analysts cannot read templates. A denied request creates an event and
          alert.
        </p>
      )}
    </Modal>
  );
}
function Intelligence({ run, busy }) {
  const [result, setResult] = useState(null);
  return (
    <div className="intelligence-grid">
      <section className="panel intelligence-form">
        <Globe size={36} className="mint" />
        <h2>Public IP enrichment</h2>
        <p>
          Query existing InternetDB observations for a public IPv4 address. Only
          the entered IP is sent to Shodan; test identities and template IDs
          stay local.
        </p>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setResult(null);
            const r = await run(() =>
              api(
                "/enrichment/" +
                  encodeURIComponent(new FormData(e.currentTarget).get("ip")),
              ),
            );
            if (r) setResult(r);
          }}
        >
          <label>
            Public IPv4 address
            <input name="ip" placeholder="e.g. 8.8.8.8" required />
          </label>
          <button className="primary" disabled={busy}>
            <Search size={16} />
            {busy ? "Looking up…" : "Look up IP"}
          </button>
        </form>
        <small>
          Synthetic and private IPs are never submitted externally. External
          observations are context, not proof of compromise.
        </small>
        <a href="https://osintframework.com/" target="_blank" rel="noreferrer">
          Explore OSINT Framework <ExternalLink size={14} />
        </a>
      </section>
      <section className="panel enrichment-results">
        <div className="panel-heading">
          <h2>Intelligence results</h2>
          <span className="outline-tag">SHODAN INTERNETDB</span>
        </div>
        {!result ? (
          <Empty>Run a lookup to view public observations.</Empty>
        ) : result.status !== "ok" ? (
          <Empty>{result.message}</Empty>
        ) : (
          <div className="enrichment-content">
            <h3 className="mono">{result.ip}</h3>
            {["ports", "hostnames", "tags", "vulns"].map((k) => (
              <div key={k}>
                <span className="eyebrow">{k}</span>
                <p>
                  {result[k].length
                    ? result[k].join(", ")
                    : "No observations reported"}
                </p>
              </div>
            ))}
            <p className="subtle">
              Source: Shodan InternetDB. Vulnerability observations may be
              unverified.
            </p>
          </div>
        )}
      </section>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);

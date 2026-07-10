import { useEffect, useState } from "react";

function Card({ title, value, subtitle }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg shadow-black/20">
      <p className="text-sm text-slate-400">{title}</p>
      <p className="mt-2 text-3xl font-semibold text-white">{value}</p>
      <p className="mt-2 text-sm text-slate-500">{subtitle}</p>
    </div>
  );
}

export default function App() {
  const [summary, setSummary] = useState(null);
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadDashboard() {
      try {
        const [summaryResponse, scansResponse, findingsResponse] =
          await Promise.all([
            fetch("/api/dashboard/summary"),
            fetch("/api/dashboard/scans"),
            fetch("/api/dashboard/findings"),
          ]);

        const summaryData = await summaryResponse.json();
        const scansData = await scansResponse.json();
        const findingsData = await findingsResponse.json();

        setSummary(summaryData);
        setScans(scansData);
        setFindings(findingsData);
      } catch (error) {
        console.error(error);
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 p-8 text-white">
        Loading dashboard...
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 p-6 text-white sm:p-8">
      <div className="mx-auto max-w-7xl">
        <header className="mb-8 rounded-3xl border border-slate-800 bg-gradient-to-br from-slate-900 to-slate-800 p-8 shadow-2xl shadow-black/20">
          <p className="text-sm uppercase tracking-[0.3em] text-cyan-400">
            GitSentry
          </p>
          <h1 className="mt-3 text-4xl font-semibold">
            Security review dashboard
          </h1>
          <p className="mt-3 max-w-2xl text-slate-400">
            Monitor pull-request scans, view findings, and keep your GitHub
            security workflow visible in one place.
          </p>
        </header>

        <section className="mb-8 grid gap-4 md:grid-cols-3">
          <Card
            title="Total scans"
            value={summary?.totalScans ?? 0}
            subtitle="Recorded webhook runs"
          />
          <Card
            title="Findings"
            value={summary?.totalFindings ?? 0}
            subtitle="Secrets and dependency alerts"
          />
          <Card
            title="Tracked repos"
            value={summary?.repositories ?? 0}
            subtitle={`Latest status: ${summary?.latestStatus ?? "idle"}`}
          />
        </section>

        <section className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 shadow-lg shadow-black/20">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-xl font-semibold">Recent scans</h2>
              <span className="text-sm text-slate-500">
                Live from your webhook pipeline
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-800 text-left text-slate-400">
                    <th className="pb-3">Repo</th>
                    <th className="pb-3">PR</th>
                    <th className="pb-3">Status</th>
                    <th className="pb-3">Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((scan) => (
                    <tr
                      key={scan.id}
                      className="border-b border-slate-800/70 text-slate-300"
                    >
                      <td className="py-3">{scan.repository}</td>
                      <td className="py-3">#{scan.pullRequest}</td>
                      <td className="py-3">{scan.status}</td>
                      <td className="py-3">{scan.findingsCount ?? 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 shadow-lg shadow-black/20">
            <h2 className="mb-4 text-xl font-semibold">Latest findings</h2>
            <div className="space-y-3">
              {findings.map((finding) => (
                <div
                  key={finding.id}
                  className="rounded-xl border border-slate-800 bg-slate-950/80 p-3"
                >
                  <div className="flex items-center justify-between">
                    <p className="font-medium text-white">{finding.title}</p>
                    <span className="rounded-full bg-slate-800 px-2 py-1 text-xs uppercase text-slate-300">
                      {finding.severity}
                    </span>
                  </div>
                  <p className="mt-1 text-sm text-slate-400">
                    {finding.type} • {finding.file}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ShieldAlert, Activity, GitBranch } from 'lucide-react';
import { useDashboardData } from './hooks/useDashboardData';
import { useDashboardStore } from './stores/useDashboardStore';
import Layout from './components/Layout';
import StatsCard from './components/StatsCard';
import FindingsTrendChart from './components/charts/FindingsTrendChart';
import SeverityBreakdownChart from './components/charts/SeverityBreakdownChart';
import FindingTypesPieChart from './components/charts/FindingTypesPieChart';
import ScansTable from './components/ScansTable';
import FindingsTable from './components/FindingsTable';

const queryClient = new QueryClient();

function DashboardContent() {
  const { isLoading, isError } = useDashboardData();
  const summary = useDashboardStore(state => state.summary);
  const findings = useDashboardStore(state => state.findings);
  
  if (isLoading && !summary) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="animate-pulse flex flex-col items-center">
          <div className="w-12 h-12 border-4 border-accent-orange border-t-transparent rounded-full animate-spin mb-4"></div>
          <p className="text-text-secondary">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (isError && !summary) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="bg-accent-red/10 border border-accent-red/20 p-6 rounded-xl text-center max-w-md">
          <ShieldAlert className="w-10 h-10 text-accent-red mx-auto mb-3" />
          <h3 className="text-lg font-medium text-text-primary">Failed to load data</h3>
          <p className="text-sm text-text-secondary mt-2">Could not connect to the GitSentry backend. Please check if the server is running.</p>
        </div>
      </div>
    );
  }

  const criticalFindings = findings.filter(f => f.severity === 'critical').length;
  const recentFindingsTrend = findings.length > 0 ? 5 : 0; // Mock trend for demo

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700 ease-out">
      {/* Hero Section */}
      <section className="relative overflow-hidden glass-panel-elevated p-8 md:p-12 rounded-3xl bg-glow-orange">
        <div className="relative z-10 max-w-3xl">
          <h1 className="text-4xl md:text-5xl font-bold text-text-primary tracking-tight mb-4 text-glow">
            Security Intelligence
          </h1>
          <p className="text-lg text-text-secondary mb-8 max-w-2xl leading-relaxed">
            Real-time monitoring of your pull request pipeline. Instantly catch exposed secrets and vulnerable dependencies before they reach production.
          </p>
        </div>
      </section>

      {/* Metrics Row */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <StatsCard 
          title="Total Scans" 
          value={summary?.totalScans || 0} 
          subtitle="All-time pull requests analyzed"
          icon={Activity}
        />
        <StatsCard 
          title="Active Findings" 
          value={summary?.totalFindings || 0} 
          subtitle={`${criticalFindings} critical vulnerabilities`}
          icon={ShieldAlert}
          trend={recentFindingsTrend}
        />
        <StatsCard 
          title="Tracked Repos" 
          value={summary?.repositories || 0} 
          subtitle="Secured by GitSentry"
          icon={GitBranch}
        />
      </section>

      {/* Charts Row */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <FindingTypesPieChart />
        </div>
        <div className="lg:col-span-1">
          <SeverityBreakdownChart />
        </div>
        <div className="lg:col-span-1">
          <FindingsTrendChart />
        </div>
      </section>

      {/* Tables Row */}
      <section className="space-y-8">
        <FindingsTable />
        <ScansTable />
      </section>
    </div>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Layout>
        <DashboardContent />
      </Layout>
    </QueryClientProvider>
  );
}

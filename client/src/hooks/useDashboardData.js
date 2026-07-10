import { useQuery } from '@tanstack/react-query';
import { useEffect } from 'react';
import { useDashboardStore } from '../stores/useDashboardStore';

const fetchJson = async (url) => {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch ${url}`);
  return res.json();
};

export function useDashboardData() {
  const setSummary = useDashboardStore(state => state.setSummary);
  const setScans = useDashboardStore(state => state.setScans);
  const setFindings = useDashboardStore(state => state.setFindings);

  const { data: summary, isLoading: loadingSummary, isError: errorSummary } = useQuery({
    queryKey: ['summary'],
    queryFn: () => fetchJson('/api/dashboard/summary'),
    refetchInterval: 30000,
  });

  const { data: scans, isLoading: loadingScans, isError: errorScans } = useQuery({
    queryKey: ['scans'],
    queryFn: () => fetchJson('/api/dashboard/scans'),
    refetchInterval: 30000,
  });

  const { data: findings, isLoading: loadingFindings, isError: errorFindings } = useQuery({
    queryKey: ['findings'],
    queryFn: () => fetchJson('/api/dashboard/findings'),
    refetchInterval: 30000,
  });

  // Sync to zustand
  useEffect(() => {
    if (summary) setSummary(summary);
  }, [summary, setSummary]);

  useEffect(() => {
    if (scans) setScans(scans);
  }, [scans, setScans]);

  useEffect(() => {
    if (findings) setFindings(findings);
  }, [findings, setFindings]);

  return {
    isLoading: loadingSummary || loadingScans || loadingFindings,
    isError: errorSummary || errorScans || errorFindings,
  };
}

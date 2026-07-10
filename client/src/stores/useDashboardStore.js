import { create } from 'zustand';

export const useDashboardStore = create((set) => ({
  summary: null,
  scans: [],
  findings: [],

  filters: {
    search: '',
    severity: [],
    type: 'all',
  },

  setSummary: (summary) => set({ summary }),
  setScans: (scans) => set({ scans }),
  setFindings: (findings) => set({ findings }),

  setFilter: (key, value) => set((state) => ({
    filters: { ...state.filters, [key]: value }
  })),
  clearFilters: () => set({
    filters: {
      search: '',
      severity: [],
      type: 'all',
    }
  })
}));

// Selectors
export const selectFindingsByType = (state) => {
  const secrets = state.findings.filter(f => f.category === 'secret').length;
  const dependencies = state.findings.filter(f => f.category === 'dependency').length;
  return [
    { name: 'Secrets', value: secrets, fill: 'var(--accent-orange)' },
    { name: 'Dependencies', value: dependencies, fill: 'var(--accent-purple)' }
  ];
};

export const selectFindingsBySeverity = (state) => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  state.findings.forEach(f => {
    const sev = f.severity?.toLowerCase() || 'low';
    if (counts[sev] !== undefined) counts[sev]++;
  });
  return [
    { name: 'Critical', value: counts.critical, fill: 'var(--accent-red)' },
    { name: 'High', value: counts.high, fill: 'var(--accent-orange)' },
    { name: 'Medium', value: counts.medium, fill: 'var(--accent-yellow)' },
    { name: 'Low', value: counts.low, fill: 'var(--accent-green)' },
  ];
};

export const selectFilteredFindings = (state) => {
  return state.findings.filter(f => {
    if (state.filters.type !== 'all' && f.category !== state.filters.type) return false;
    if (state.filters.severity.length > 0 && !state.filters.severity.includes(f.severity?.toLowerCase())) return false;
    if (state.filters.search) {
      const q = state.filters.search.toLowerCase();
      return f.file?.toLowerCase().includes(q) || f.type?.toLowerCase().includes(q) || f.content?.toLowerCase().includes(q);
    }
    return true;
  });
};

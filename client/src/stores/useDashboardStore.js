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



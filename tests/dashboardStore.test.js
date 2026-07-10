const test = require("node:test");
const assert = require("node:assert/strict");
const { createMemoryStore } = require("../src/dashboard/store");

test("stores a scan and returns a summary", async () => {
  const store = createMemoryStore();

  await store.saveScanResult({
    repository: "octo/demo",
    pullRequest: 42,
    status: "ok",
    findingsCount: 2,
    findings: [
      { type: "secret", severity: "high" },
      { type: "dependency", severity: "medium" },
    ],
  });

  const summary = await store.getDashboardSummary();
  const scans = await store.getRecentScans();

  assert.equal(summary.totalScans, 1);
  assert.equal(summary.totalFindings, 2);
  assert.equal(summary.repositories, 1);
  assert.equal(scans[0].repository, "octo/demo");
  assert.equal(scans[0].pullRequest, 42);
});

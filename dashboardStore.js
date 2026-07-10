const { Client } = require("pg");

class MemoryDashboardStore {
  constructor() {
    this.scans = [];
    this.findings = [];
  }

  async saveScanResult({
    repository,
    pullRequest,
    status,
    findingsCount,
    findings = [],
  }) {
    const scan = {
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      repository,
      pullRequest,
      status,
      findingsCount,
      scannedAt: new Date().toISOString(),
    };

    this.scans.unshift(scan);
    this.findings.push(
      ...findings.map((finding, index) => ({
        id: `${scan.id}-${index}`,
        scanId: scan.id,
        type: finding.type,
        severity: finding.severity || "unknown",
        title: finding.title || finding.type,
        file: finding.file || "unknown",
      })),
    );

    return scan;
  }

  async getDashboardSummary() {
    const repositories = new Set(this.scans.map((scan) => scan.repository));
    const totalFindings = this.findings.length;
    const recentStatus = this.scans[0]?.status || "idle";

    return {
      totalScans: this.scans.length,
      totalFindings,
      repositories: repositories.size,
      latestStatus: recentStatus,
    };
  }

  async getRecentScans(limit = 10) {
    return this.scans.slice(0, limit).map((scan) => ({
      ...scan,
      findingCount: this.findings.filter(
        (finding) => finding.scanId === scan.id,
      ).length,
    }));
  }

  async getRecentFindings(limit = 10) {
    return this.findings.slice(-limit).reverse();
  }
}

class PostgresDashboardStore {
  constructor(connectionString) {
    this.client = new Client({ connectionString });
  }

  async connect() {
    if (!this.client._connected) {
      await this.client.connect();
      this.client._connected = true;
    }
  }

  async ensureSchema() {
    await this.connect();
    await this.client.query(`
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        repository TEXT NOT NULL,
        pull_request INTEGER NOT NULL,
        status TEXT NOT NULL,
        findings_count INTEGER NOT NULL,
        scanned_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
    `);
    await this.client.query(`
      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        file TEXT NOT NULL
      );
    `);
  }

  async saveScanResult({
    repository,
    pullRequest,
    status,
    findingsCount,
    findings = [],
  }) {
    await this.ensureSchema();
    const scanId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    await this.client.query(
      "INSERT INTO scans (id, repository, pull_request, status, findings_count) VALUES ($1, $2, $3, $4, $5)",
      [scanId, repository, pullRequest, status, findingsCount],
    );

    for (const [index, finding] of findings.entries()) {
      const findingId = `${scanId}-${index}`;
      await this.client.query(
        "INSERT INTO findings (id, scan_id, type, severity, title, file) VALUES ($1, $2, $3, $4, $5, $6)",
        [
          findingId,
          scanId,
          finding.type,
          finding.severity || "unknown",
          finding.title || finding.type,
          finding.file || "unknown",
        ],
      );
    }

    return {
      id: scanId,
      repository,
      pullRequest,
      status,
      findingsCount,
      scannedAt: new Date().toISOString(),
    };
  }

  async getDashboardSummary() {
    await this.ensureSchema();
    const [{ total_scans, total_findings, repositories }] = await this.client
      .query(`
      SELECT
        COUNT(*)::int AS total_scans,
        (SELECT COUNT(*)::int FROM findings) AS total_findings,
        (SELECT COUNT(DISTINCT repository)::int FROM scans) AS repositories
      FROM scans
    `);

    const latestResult = await this.client.query(
      "SELECT status FROM scans ORDER BY scanned_at DESC LIMIT 1",
    );

    return {
      totalScans: Number(total_scans),
      totalFindings: Number(total_findings),
      repositories: Number(repositories),
      latestStatus: latestResult.rows[0]?.status || "idle",
    };
  }

  async getRecentScans(limit = 10) {
    await this.ensureSchema();
    const result = await this.client.query(
      'SELECT id, repository, pull_request AS "pullRequest", status, findings_count AS "findingsCount", scanned_at AS "scannedAt" FROM scans ORDER BY scanned_at DESC LIMIT $1',
      [limit],
    );
    return result.rows;
  }

  async getRecentFindings(limit = 10) {
    await this.ensureSchema();
    const result = await this.client.query(
      'SELECT id, scan_id AS "scanId", type, severity, title, file FROM findings ORDER BY id DESC LIMIT $1',
      [limit],
    );
    return result.rows;
  }
}

function createDashboardStore(connectionString = process.env.DATABASE_URL) {
  if (connectionString) {
    return new PostgresDashboardStore(connectionString);
  }

  return createMemoryStore();
}

function createMemoryStore() {
  return new MemoryDashboardStore();
}

module.exports = {
  createDashboardStore,
  createMemoryStore,
};

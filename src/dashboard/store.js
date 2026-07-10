const { Pool } = require('pg');

/**
 * Creates a dashboard store that abstracts over PostgreSQL and an in-memory
 * fallback.
 *
 * When `DATABASE_URL` is set in the environment a `pg.Pool` is lazily
 * initialised on the first query. When it is absent all write operations
 * are no-ops and all read operations return empty arrays, so the webhook
 * processor continues to work without any database infrastructure.
 *
 * @returns {{ getDashboardSummary: Function, getRecentScans: Function,
 *             getRecentFindings: Function, saveScanResult: Function,
 *             closePool: Function }} The store API.
 */
function createDashboardStore() {
  let pool = null;

  function getPool() {
    if (!pool) {
      const connectionString = process.env.DATABASE_URL;
      if (connectionString) {
        pool = new Pool({
          connectionString,
          max: 10,
          idleTimeoutMillis: 30000,
          connectionTimeoutMillis: 5000,
        });
        console.log('✅ PostgreSQL pool created');
      } else {
        console.warn('⚠️ DATABASE_URL not set, using in-memory store');
      }
    }
    return pool;
  }

  async function query(text, params) {
    const client = getPool();
    if (!client) {
      return { rows: [] };
    }
    try {
      const res = await client.query(text, params);
      return res;
    } catch (err) {
      console.error('Database query error:', err);
      throw err;
    }
  }

  // ─── Dashboard Store Functions ──────────────────────────────

  /**
   * Returns aggregate scan metrics.
   * @returns {Promise<{totalScans: number}>}
   */
  async function getDashboardSummary() {
    const result = await query('SELECT COUNT(*) as total FROM scans');
    return {
      totalScans: result.rows[0]?.total || 0,
    };
  }

  /**
   * Returns the most recent scans in descending chronological order.
   * @param {number} [limit=10] - Maximum number of records to return.
   * @returns {Promise<object[]>}
   */
  async function getRecentScans(limit = 10) {
    const result = await query(
      'SELECT * FROM scans ORDER BY created_at DESC LIMIT $1',
      [limit]
    );
    return result.rows;
  }

  /**
   * Returns the most recent findings in descending chronological order.
   * @param {number} [limit=20] - Maximum number of records to return.
   * @returns {Promise<object[]>}
   */
  async function getRecentFindings(limit = 20) {
    const result = await query(
      'SELECT * FROM findings ORDER BY created_at DESC LIMIT $1',
      [limit]
    );
    return result.rows;
  }

  /**
   * Atomically persists a completed scan and all of its findings.
   *
   * Wraps the inserts in a database transaction — if any finding insert
   * fails the entire scan record is rolled back.
   *
   * @param {{ repository: string, pullRequest: number, status: string,
   *           findingsCount: number, findings: object[] }} scanData
   * @returns {Promise<void>}
   */
  async function saveScanResult(scanData) {
    const { repository, pullRequest, status, findingsCount, findings } = scanData;
    const client = getPool();
    if (!client) {
      console.log('In-memory save (no DB)');
      return;
    }

    const dbClient = await client.connect();
    try {
      await dbClient.query('BEGIN');
      const scanResult = await dbClient.query(
        `INSERT INTO scans (repository, pull_request, status, findings_count)
         VALUES ($1, $2, $3, $4) RETURNING id`,
        [repository, pullRequest, status, findingsCount]
      );
      const scanId = scanResult.rows[0].id;
      for (const finding of findings) {
        await dbClient.query(
          `INSERT INTO findings (scan_id, type, severity, file, line, content, cve)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [scanId, finding.type, finding.severity, finding.file, finding.line, finding.content, finding.cve]
        );
      }
      await dbClient.query('COMMIT');
    } catch (err) {
      await dbClient.query('ROLLBACK');
      throw err;
    } finally {
      dbClient.release();
    }
  }

  async function closePool() {
    if (pool) {
      await pool.end();
      pool = null;
    }
  }

  // ─── Return the public API ──────────────────────────────────
  return {
    getDashboardSummary,
    getRecentScans,
    getRecentFindings,
    saveScanResult,
    closePool,
  };
}

module.exports = { createDashboardStore };

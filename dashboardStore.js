const { Pool } = require('pg');

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

async function getDashboardSummary() {
  const result = await query('SELECT COUNT(*) as total FROM scans');
  return {
    totalScans: result.rows[0]?.total || 0,
  };
}

async function getRecentScans(limit = 10) {
  const result = await query(
    'SELECT * FROM scans ORDER BY created_at DESC LIMIT $1',
    [limit]
  );
  return result.rows;
}

async function getRecentFindings(limit = 20) {
  const result = await query(
    'SELECT * FROM findings ORDER BY created_at DESC LIMIT $1',
    [limit]
  );
  return result.rows;
}

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

module.exports = {
  getDashboardSummary,
  getRecentScans,
  getRecentFindings,
  saveScanResult,
  closePool: async () => {
    if (pool) {
      await pool.end();
      pool = null;
    }
  }
};
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { runScan } = require("./scanner");
const { validateTarget } = require("./validation");
const pool = require("./db");

const app = express();
app.use(express.json());
app.use(cors({ origin: "http://localhost:5173" }));
const API_KEY = process.env.API_KEY || "demo-key-123";

function requireApiKey(req, res, next) {
  if (req.get("x-api-key") !== API_KEY) {
    return res.status(401).json({
      error: { code: "UNAUTHORIZED", message: "Missing or invalid API key." },
    });
  }
  next();
}

app.use("/api/scans", requireApiKey);

const scanLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 scan requests per minute per client
  message: {
    error: { code: "RATE_LIMITED", message: "Too many requests. Try again later." },
  },
});

const scans = {};
let counter = 0;

async function loadCounter() {
  try {
    const r = await pool.query("SELECT COUNT(*) FROM scans");
    counter = Number(r.rows[0].count);
  } catch (e) {
    console.error("Could not load counter:", e.message);
  }
}
const MAX_CONCURRENT_SCANS = 2;
const SCAN_TIMEOUT_MS = 80000; // 80 seconds
let runningScans = 0;

async function saveScan(scan) {
  try {
    await pool.query(
      `INSERT INTO scans (id, target, status, completed_at, error_message)
       VALUES ($1, $2, $3, NOW(), $4)
       ON CONFLICT (id) DO UPDATE
       SET status = $3, completed_at = NOW(), error_message = $4`,
      [scan.scan_id, scan.target, scan.status, scan.error || null]
    );

    for (const f of scan.findings) {
      await pool.query(
        `INSERT INTO findings
         (scan_id, finding_id, title, port, protocol, service, severity, evidence, confidence, recommendation)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [scan.scan_id, f.finding_id, f.title, f.port, f.protocol, f.service,
        f.severity, f.evidence, f.confidence, f.recommendation]
      );
    }
  } catch (e) {
    console.error("Database save failed:", e.message);
  }
}

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

app.post("/api/scans", scanLimiter, (req, res) => {
  const result = validateTarget(req.body.target);
  if (!result.ok) {
    return res.status(result.status).json({
      error: { code: result.code, message: result.message },
    });
  }

  if (runningScans >= MAX_CONCURRENT_SCANS) {
    return res.status(429).json({
      error: { code: "TOO_MANY_SCANS", message: "Too many scans running. Try again later." },
    });
  }

  const target = result.target;
  counter++;
  const scan_id = `scan-${String(counter).padStart(3, "0")}`;

  scans[scan_id] = { scan_id, target, status: "running", findings: [] };
  runningScans++;

  const timer = setTimeout(() => {
    if (scans[scan_id].status === "running") {
      scans[scan_id].status = "timed_out";
      runningScans--;
      saveScan(scans[scan_id]);
    }
  }, SCAN_TIMEOUT_MS);

  runScan(target)
    .then((findings) => {
      if (scans[scan_id].status === "running") {
        clearTimeout(timer);
        scans[scan_id].findings = findings;
        scans[scan_id].status = "completed";
        runningScans--;
        saveScan(scans[scan_id]);
      }
    })
      .catch((err) => {
      if (scans[scan_id].status === "running") {
        clearTimeout(timer);
        scans[scan_id].status = "failed";
        scans[scan_id].error = err.message;
        runningScans--;
        saveScan(scans[scan_id]);
      }
    });

  res.status(202).json({ scan_id, target, status: "running" });
});
app.get("/api/scans", async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT id, target, status, started_at, completed_at, error_message FROM scans ORDER BY started_at DESC LIMIT 50"
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({
      error: { code: "SERVER_ERROR", message: "Could not load scan history." },
    });
  }
});
app.get("/api/scans/:id", (req, res) => {
  const scan = scans[req.params.id];
  if (!scan) {
    return res.status(404).json({
      error: { code: "SCAN_NOT_FOUND", message: "Scan not found." },
    });
  }
  res.json(scan);
});

// Handle malformed JSON and other unexpected errors
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({
      error: { code: "INVALID_JSON", message: "The request body is not valid JSON." },
    });
  }
  res.status(500).json({
    error: { code: "SERVER_ERROR", message: "Something went wrong." },
  });
});

loadCounter().then(() => {
  app.listen(3000, () => console.log("API running on port 3000"));
});
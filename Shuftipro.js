// ShuftiProKyc.js — STATIC • SIMPLE • CLEAN (created_at GSI, no ScanIndexForward)
// - One table, one GSI (“gsi_meta”) for all rows tied to a Shufti reference
// - Keys configured up-front (dev-friendly): CONFIG.KEYS = { pk, sk, gsi_meta:{ name, pk, sk } }
// - Sort by datetime: we store ISO in created_at and reverse in Node (NO ScanIndexForward anywhere)
// - Logger.writeLog(...) for info/decision; ErrorHandler.add_error(...) ONLY for real failures
// - Uses your helpers directly: Formatting.sanitizeValidate, ScyllaDb.*, Logger, ErrorHandler
// - Document-only KYC (no face)

// ===== Requires (CJS). Swap to ESM ‘import’ if your app expects that. =====
const ScyllaDb     = require("./ScyllaDb");        // putItem, getItem, deleteItem, query
const Formatting   = require("./formatting");      // sanitizeValidate(defMap)
const ErrorHandler = require("./ErrorHandler");    // add_error(message, data?)
const Logger       = require("./Logger Final");    // writeLog({ flag, action, message, data, critical? })
const crypto       = require("crypto");

// ===== Config (all key field names + GSI definition here) ====================
let CONFIG = {
  TABLE: "kyc_shufti",

  KEYS: {
    // Primary index (timeline, meta row)
    pk: "pk",
    sk: "sk",

    // GSI that groups ALL rows for a single Shufti reference
    // pk = reference, sk = created_at (ISO string), so we can time-sort after query in Node.
    gsi_meta: { name: "GSI1", pk: "ppk", sk: "created_at" },
  },

  LOG_FLAGS: {
    request:   "kyc_request",
    webhook:   "kyc_webhook",
    status:    "kyc_status",
    ratelimit: "kyc_rate_limit",
    error:     "kyc_error",
  },

  // API / behavior
  CLIENT_ID: "",
  SECRET_KEY: "",
  API_URL: "https://api.shuftipro.com/",
  CALLBACK_URL: "",
  REDIRECT_URL: "",
  HTTP_TIMEOUT_MS: 15000,

  DEFAULT_LANGUAGE: "en",
  LOCALE_MAP: {
    en: "en", "en-AU": "en", "en-GB": "en", "en-US": "en",
    zh: "zh", "zh-CN": "zh", "zh-TW": "zh",
    ja: "ja", ko: "ko", tl: "tl",
    fr: "fr", de: "de", es: "es", it: "it", pt: "pt", ru: "ru",
  },

  // Local (client-side) rate alert
  PER_MINUTE_LIMIT: 60,
  SLACK_WEBHOOK_URL: null,
};

// ===== Shufti Events =========================================================
const KYC_EVENT = {
  REQUEST_PENDING: "request.pending",
  REQUEST_INVALID: "request.invalid",
  REQUEST_UNAUTHORIZED: "request.unauthorized",
  REQUEST_TIMEOUT: "request.timeout",
  REQUEST_DELETED: "request.deleted",
  REQUEST_RECEIVED: "request.received",
  REQUEST_DATA_CHANGED: "request.data.changed",
  VERIFICATION_ACCEPTED: "verification.accepted",
  VERIFICATION_DECLINED: "verification.declined",
  VERIFICATION_STATUS_CHANGED: "verification.status.changed",
  VERIFICATION_CANCELLED: "verification.cancelled",
  REVIEW_PENDING: "review.pending",
};

// “Active/in-progress” → reuse instead of spawning a new session
const ACTIVE_EVENTS = new Set([
  KYC_EVENT.REQUEST_PENDING,
  KYC_EVENT.REQUEST_RECEIVED,
  KYC_EVENT.REVIEW_PENDING,
  KYC_EVENT.VERIFICATION_STATUS_CHANGED,
]);

// Local request timestamps for naive per-minute threshold alerting
const LOCAL_REQUEST_TIMESTAMPS = [];

// ============================================================================
// CLASS
// ============================================================================
class ShuftiProKyc {
  static configure(options = {}) {
    CONFIG = { ...CONFIG, ...options };
    if (!/^https?:\/\//i.test(CONFIG.API_URL)) CONFIG.API_URL = "https://api.shuftipro.com/";
    if (!CONFIG.API_URL.endsWith("/")) CONFIG.API_URL += "/";
    Logger.writeLog({
      flag: CONFIG.LOG_FLAGS.request,
      action: "configure",
      message: "KYC configured",
      data: { api: CONFIG.API_URL, callback: !!CONFIG.CALLBACK_URL, table: CONFIG.TABLE }
    });
  }

  /**
   * createVerificationSession
   * - Reuse ACCEPTED or ACTIVE attempt if it exists
   * - Otherwise create a NEW Shufti session
   *
   * Returns one of:
   *  { alreadyValidated: true, reference, status, verificationUrl }
   *  { alreadyHasActive: true, reference, status, verificationUrl }
   *  { reference, verificationUrl }
   */
  static async createVerificationSession({
    userId,
    userEmail,
    appLocale,
    userCountry = "",
    verificationMode = "any",
    documentConfig = {},
  }) {
    // Validate inputs via your helper (explicit types/required)
    const clean = Formatting.sanitizeValidate({
      userId:           { value: userId,        type: "string", required: true },
      userEmail:        { value: userEmail,     type: "email",  required: true },
      appLocale:        { value: appLocale ?? null, type: "string", required: false, default: null },
      userCountry:      { value: userCountry ?? "", type: "string", required: false, default: "" },
      verificationMode: { value: verificationMode ?? "any", type: "string", required: false, default: "any" },
    });

    const { pk, sk, gsi_meta } = CONFIG.KEYS;

    // 1) REUSE if ACCEPTED or ACTIVE exists
    //    We fetch the user's timeline (primary index), then check meta via GSI, then pick the latest in Node.
    const timeline = await ScyllaDb.query(
      CONFIG.TABLE,
      `${pk} = :pk`,
      { ":pk": `user_${clean.userId}` },
      { Limit: 50 } // NO ScanIndexForward; we'll reverse/process in Node as needed
    );

    const sortedTimeline = Array.isArray(timeline) ? timeline.slice().reverse() : []; // newest last? normalize by reversing
    let activeCandidate = null;

    for (const item of sortedTimeline) {
      if (item.type !== "verification_request") continue;

      // Fetch rows for this reference (GSI: ppk = reference). We get multiple rows, pick the meta row if present.
      const byRef = await ScyllaDb.query(
        CONFIG.TABLE,
        `${gsi_meta.pk} = :ref`,
        { ":ref": item.reference },
        { IndexName: gsi_meta.name }
      );
      const latestByRef = Array.isArray(byRef) ? byRef.slice().reverse() : [];
      const meta = pickMeta(latestByRef) || latestByRef[0] || null;

      const status = meta?.status || item.event || "unknown";
      const verificationUrl = meta?.verificationUrl ?? item.verificationUrl ?? null;

      if (status === KYC_EVENT.VERIFICATION_ACCEPTED) {
        Logger.writeLog({
          flag: CONFIG.LOG_FLAGS.request,
          action: "reuse_accepted",
          message: "User already verified; returning accepted session",
          data: { userId: clean.userId, reference: item.reference }
        });
        return { alreadyValidated: true, reference: item.reference, status, verificationUrl };
      }
      if (!activeCandidate && ACTIVE_EVENTS.has(status)) {
        activeCandidate = { alreadyHasActive: true, reference: item.reference, status, verificationUrl };
      }
    }

    if (activeCandidate) {
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.request,
        action: "reuse_active",
        message: "Active verification session exists; reusing",
        data: { userId: clean.userId, reference: activeCandidate.reference, status: activeCandidate.status }
      });
      return activeCandidate;
    }

    // 2) CREATE a new session
    await registerLocalRateAndMaybeAlert("createVerificationSession");

    const reference   = generateReference();
    const language    = normalizeLocaleToLanguage(clean.appLocale || CONFIG.DEFAULT_LANGUAGE);
    const created_at  = new Date().toISOString();

    const payload = {
      reference,
      email: clean.userEmail,
      country: clean.userCountry,
      language,
      verification_mode: clean.verificationMode,

      // Flow defaults
      allow_offline: "1",
      allow_online: "1",
      show_privacy_policy: "0",
      show_results: "1",
      show_consent: "0",
      show_feedback_form: "0",
      manual_review: "0",

      ...(CONFIG.CALLBACK_URL ? { callback_url: CONFIG.CALLBACK_URL } : {}),
      ...(CONFIG.REDIRECT_URL ? { redirect_url: CONFIG.REDIRECT_URL } : {}),

      // Document only (no face)
      document: {
        name: documentConfig.name ?? "",
        dob: documentConfig.dob ?? "",
        fetch_enhanced_data: documentConfig.fetch_enhanced_data ?? "1",
        supported_types: documentConfig.supported_types ?? ["id_card", "driving_license", "passport"],
        verification_instructions: {
          allow_paper_based: "1",
          allow_photocopy: "1",
          allow_colorcopy: "1",
          allow_black_and_white: "1",
          allow_laminated: "1",
          allow_screenshot: "1",
          allow_cropped: "1",
          allow_scanned: "1",
          allow_e_document: "1",
          allow_handwritten_document: "1",
          ...(documentConfig.verification_instructions || {}),
        },
      },
    };

    Logger.writeLog({
      flag: CONFIG.LOG_FLAGS.request,
      action: "create_new",
      message: "Creating new Shufti session",
      data: { userId: clean.userId, reference }
    });

    // HTTP to Shufti (Basic auth)
    const authHeader = "Basic " + Buffer.from(`${CONFIG.CLIENT_ID}:${CONFIG.SECRET_KEY}`, "utf8").toString("base64");
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), CONFIG.HTTP_TIMEOUT_MS);

    let res;
    try {
      res = await fetch(CONFIG.API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": authHeader },
        body: JSON.stringify(payload),
        signal: ctrl.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      ErrorHandler.add_error("KYC network error (createVerificationSession)", {
        userId: clean.userId, reference, error: String(err)
      });
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "network_error",
        message: "Network error contacting Shufti",
        data: { userId: clean.userId, reference, error: String(err) },
        critical: true
      });
      throw err;
    }
    clearTimeout(timer);

    const signatureHeader = res.headers.get("signature") || res.headers.get("Signature") || "";
    const rawBody = await res.text();

    let parsed;
    try {
      parsed = rawBody ? JSON.parse(rawBody) : {};
    } catch (e) {
      ErrorHandler.add_error("KYC response invalid JSON", {
        userId: clean.userId, reference, snippet: rawBody?.slice(0, 500)
      });
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "invalid_json",
        message: "Shufti returned invalid JSON",
        data: { userId: clean.userId, reference },
        critical: true
      });
      throw e;
    }

    if (!res.ok) {
      // Not fatal for flow, but is an error condition to record
      ErrorHandler.add_error("KYC response non-200", {
        userId: clean.userId, reference, status: res.status, parsed
      });
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "non_200",
        message: "Shufti returned non-200",
        data: { userId: clean.userId, reference, status: res.status }
      });
    }

    if (!verifyShuftiSignature(rawBody, signatureHeader)) {
      ErrorHandler.add_error("KYC response signature invalid", { userId: clean.userId, reference });
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "invalid_signature",
        message: "Invalid signature in Shufti response",
        data: { userId: clean.userId, reference },
        critical: true
      });
      throw new Error("Invalid Shufti HTTP signature");
    }

    const event = parsed?.event || "unknown";
    const verificationUrl = parsed?.verification_url || null;

    // Persist attempt on user timeline
    await ScyllaDb.putItem(CONFIG.TABLE, {
      [pk]: `user_${clean.userId}`,
      [sk]: created_at,                       // natural ISO sort
      [gsi_meta.pk]: reference,
      [gsi_meta.sk]: created_at,              // GSI sort = created_at
      type: "verification_request",
      userId: clean.userId,
      reference,
      event,
      verificationUrl,
      requestPayload: payload,
      responsePayload: parsed,
      language,
      created_at,
    });

    // Upsert meta row (direct primary + GSI sentinel via same reference)
    await ScyllaDb.putItem(CONFIG.TABLE, {
      [pk]: `meta_${reference}`,
      [sk]: "meta",
      [gsi_meta.pk]: reference,
      [gsi_meta.sk]: created_at,              // keep meta time-aligned for timeline purposes
      type: "meta",
      userId: clean.userId,
      reference,
      status: event,
      verificationUrl,
      language,
      created_at,
    });

    Logger.writeLog({
      flag: CONFIG.LOG_FLAGS.request,
      action: "created",
      message: "New Shufti session created",
      data: { userId: clean.userId, reference, event }
    });

    return { reference, verificationUrl };
  }

  /**
   * handleWebhook
   * Validate signature → save webhook row → update meta
   * Returns { ok, reference, event }
   */
  static async handleWebhook({ rawBodyString, signatureHeader }) {
    Logger.writeLog({
      flag: CONFIG.LOG_FLAGS.webhook,
      action: "received",
      message: "Webhook received",
      data: { bytes: rawBodyString ? String(rawBodyString).length : 0 }
    });

    if (!verifyShuftiSignature(rawBodyString, signatureHeader)) {
      ErrorHandler.add_error("KYC webhook signature invalid");
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "invalid_signature",
        message: "Invalid signature on webhook",
        data: {},
        critical: true
      });
      return { ok: false };
    }

    let payload;
    try {
      payload = JSON.parse(rawBodyString);
    } catch {
      ErrorHandler.add_error("KYC webhook invalid JSON", { snippet: String(rawBodyString).slice(0, 500) });
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "invalid_json",
        message: "Webhook JSON parse failed",
        data: {},
        critical: true
      });
      return { ok: false };
    }

    const reference = payload?.reference || "unknown";
    const event = payload?.event || "unknown";
    const created_at = new Date().toISOString();

    const { pk, sk, gsi_meta } = CONFIG.KEYS;

    // Fetch rows for this reference; prefer the meta row if present to get userId
    const byRef = await ScyllaDb.query(
      CONFIG.TABLE,
      `${gsi_meta.pk} = :ref`,
      { ":ref": reference },
      { IndexName: gsi_meta.name }
    );
    const latestByRef = Array.isArray(byRef) ? byRef.slice().reverse() : [];
    const meta = pickMeta(latestByRef) || latestByRef[0] || null;
    const userId = meta?.userId || payload?.user_id || "unknown";

    // Write webhook row to timeline + GSI
    await ScyllaDb.putItem(CONFIG.TABLE, {
      [pk]: `user_${userId}`,
      [sk]: created_at,
      [gsi_meta.pk]: reference,
      [gsi_meta.sk]: created_at,
      type: "webhook_event",
      userId,
      reference,
      event,
      webhookPayload: payload,
      created_at,
    });

    // Update meta row
    await ScyllaDb.putItem(CONFIG.TABLE, {
      [pk]: `meta_${reference}`,
      [sk]: "meta",
      [gsi_meta.pk]: reference,
      [gsi_meta.sk]: created_at, // track last change time on GSI too
      type: "meta",
      userId,
      reference,
      status: event,
      lastEvent: event,
      lastEventAt: created_at,
      verificationUrl: meta?.verificationUrl ?? null,
      language: meta?.language ?? CONFIG.DEFAULT_LANGUAGE,
      created_at: meta?.created_at ?? created_at,
    });

    Logger.writeLog({
      flag: CONFIG.LOG_FLAGS.webhook,
      action: "stored",
      message: "Webhook stored and meta updated",
      data: { userId, reference, event }
    });

    return { ok: true, reference, event };
  }

  /**
   * getRecordByReference
   * - Returns { meta, verificationRequests, webhookEvents, statusChanges }
   */
  static async getRecordByReference(reference) {
    const { pk, sk, gsi_meta } = CONFIG.KEYS;

    const items = await ScyllaDb.query(
      CONFIG.TABLE,
      `${gsi_meta.pk} = :ref`,
      { ":ref": reference },
      { IndexName: gsi_meta.name }
    );
    if (!Array.isArray(items) || !items.length) return null;

    // Normalize newest-first for consumers
    const sorted = items.slice().reverse();

    let meta = null;
    const verificationRequests = [];
    const webhookEvents = [];
    const statusChanges = [];

    for (const item of sorted) {
      if (item.type === "meta") meta = item;
      else if (item.type === "verification_request") verificationRequests.push(item);
      else if (item.type === "webhook_event") webhookEvents.push(item);
      else if (item.type === "status_change") statusChanges.push(item);
    }

    if (!meta) {
      // Fallback direct get if meta wasn’t present in GSI scan (shouldn’t happen, but safe)
      meta = await ScyllaDb.getItem(CONFIG.TABLE, { [pk]: `meta_${reference}`, [sk]: "meta" });
    }

    return { meta, verificationRequests, webhookEvents, statusChanges };
  }

  /**
   * isUserValidated
   * - TRUE if ANY attempt in history has status === verification.accepted
   */
  static async isUserValidated(userId) {
    const { pk, gsi_meta } = CONFIG.KEYS;

    const timeline = await ScyllaDb.query(
      CONFIG.TABLE,
      `${pk} = :pk`,
      { ":pk": `user_${userId}` },
      { Limit: 50 }
    );
    if (!Array.isArray(timeline) || !timeline.length) return false;

    const sortedTimeline = timeline.slice().reverse(); // newest-first for the loop
    for (const item of sortedTimeline) {
      if (item.type !== "verification_request") continue;

      const byRef = await ScyllaDb.query(
        CONFIG.TABLE,
        `${gsi_meta.pk} = :ref`,
        { ":ref": item.reference },
        { IndexName: gsi_meta.name }
      );
      const latestByRef = Array.isArray(byRef) ? byRef.slice().reverse() : [];
      const meta = pickMeta(latestByRef) || latestByRef[0] || null;

      if (meta?.status === KYC_EVENT.VERIFICATION_ACCEPTED) return true;
    }
    return false;
  }

  /**
   * updateRecordStatus
   * - Manually update meta.status and log a status_change row
   */
  static async updateRecordStatus(reference, newStatus) {
    const { pk, sk, gsi_meta } = CONFIG.KEYS;

    const byRef = await ScyllaDb.query(
      CONFIG.TABLE,
      `${gsi_meta.pk} = :ref`,
      { ":ref": reference },
      { IndexName: gsi_meta.name }
    );
    const latestByRef = Array.isArray(byRef) ? byRef.slice().reverse() : [];
    let meta = pickMeta(latestByRef) || latestByRef[0] || null;

    if (!meta) {
      meta = await ScyllaDb.getItem(CONFIG.TABLE, { [pk]: `meta_${reference}`, [sk]: "meta" });
    }
    if (!meta) {
      ErrorHandler.add_error("KYC updateRecordStatus: meta not found", { reference, newStatus });
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "meta_missing",
        message: "Meta not found for reference during status update",
        data: { reference, newStatus }
      });
      return false;
    }

    const created_at = new Date().toISOString();

    // Update meta
    await ScyllaDb.putItem(CONFIG.TABLE, {
      [pk]: `meta_${reference}`,
      [sk]: "meta",
      [gsi_meta.pk]: reference,
      [gsi_meta.sk]: created_at,
      type: "meta",
      userId: meta.userId,
      reference,
      status: newStatus,
      lastEvent: newStatus,
      lastEventAt: created_at,
      verificationUrl: meta.verificationUrl ?? null,
      language: meta.language ?? CONFIG.DEFAULT_LANGUAGE,
      created_at: meta.created_at ?? created_at,
    });

    // Log status change on timeline
    await ScyllaDb.putItem(CONFIG.TABLE, {
      [pk]: `user_${meta.userId}`,
      [sk]: created_at,
      [gsi_meta.pk]: reference,
      [gsi_meta.sk]: created_at,
      type: "status_change",
      userId: meta.userId,
      reference,
      event: KYC_EVENT.VERIFICATION_STATUS_CHANGED,
      newStatus,
      created_at,
    });

    Logger.writeLog({
      flag: CONFIG.LOG_FLAGS.status,
      action: "updated",
      message: "Status updated + change logged",
      data: { reference, newStatus, userId: meta.userId }
    });

    return true;
  }
}

// ===== Internals (tiny, obvious) =============================================
function generateReference() {
  return `ref-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
}
function normalizeLocaleToLanguage(appLocale) {
  if (!appLocale) return CONFIG.DEFAULT_LANGUAGE;
  const key = String(appLocale).trim();
  return CONFIG.LOCALE_MAP[key] || CONFIG.LOCALE_MAP[key.split("-")[0]] || CONFIG.DEFAULT_LANGUAGE;
}
function verifyShuftiSignature(rawBodyString, signatureHeaderValue) {
  if (!rawBodyString || !signatureHeaderValue) return false;
  const inner = crypto.createHash("sha256").update(CONFIG.SECRET_KEY, "utf8").digest("hex");
  const computed = crypto.createHash("sha256").update(String(rawBodyString) + inner, "utf8").digest("hex");
  return computed === String(signatureHeaderValue).trim();
}
// prefer the “meta” row if it exists in a list
function pickMeta(items) {
  if (!Array.isArray(items)) return null;
  for (const it of items) if (it.type === "meta") return it;
  return null;
}

// ===== Exports ================================================================
module.exports = ShuftiProKyc;
module.exports.KYC_EVENT = KYC_EVENT;
module.exports.CONFIG = CONFIG;






























-------------------------
/**
 * ShuftiProKyc — Full usage & mock testing harness
 * ------------------------------------------------
 * - Runs end-to-end happy-path + edge cases entirely in-memory.
 * - Mocks: ScyllaDb (in-memory), Logger, ErrorHandler, Formatting, fetch (Shufti API).
 * - Exercises:
 *    1) Create new session (happy path)
 *    2) Reuse ACTIVE session
 *    3) Webhook accepted → user validated
 *    4) Reuse after ACCEPTED (alreadyValidated)
 *    5) Non-200 response
 *    6) Invalid JSON response
 *    7) Invalid signature response
 *    8) Network error
 *    9) Webhook invalid signature
 *   10) Webhook invalid JSON
 *   11) updateRecordStatus when meta missing
 *   12) Rate-limit breach logging
 *
 * Paste in a single Node.js file and run `node <file>`.
 * Adjust the ShuftiProKyc CONFIG at the top of test() if needed.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Mock helpers: DB, logger, error handler, formatting
// ─────────────────────────────────────────────────────────────────────────────

const InMemoryTable = new Map(); // key: tableName -> Map("pk|sk" -> item)

const ScyllaDb = {
  // Basic Dynamo-like put
  async putItem(table, item) {
    const t = tableMap(table);
    const key = `${item.pk}|${item.sk}`;
    t.set(key, deepClone(item));
    // also handle GSI fanout implicitly by storing the same row (we'll scan by attributes in query)
    return true;
  },

  async getItem(table, key) {
    const t = tableMap(table);
    const k = `${key.pk}|${key.sk}`;
    const row = t.get(k);
    return row ? deepClone(row) : null;
  },

  /**
   * Extremely simplified query:
   * - keyCondition: "<attr> = :x" OR "<attr> = :x AND begins_with(<attr2>, :y)" (we won't use begins_with here)
   * - values: {":x": "...", ":y": "..."}
   * - options: { IndexName?, Limit? } — ScanIndexForward is banned entirely, we won’t use it.
   * Behavior:
   * - If IndexName present and equals the configured GSI name, we treat `ppk` as partition and filter with that.
   * - Otherwise, we treat `pk` as partition and return all rows with that pk.
   * - We DO NOT auto-sort; caller will sort or reverse as needed.
   */
  async query(table, keyCondition, values, options = {}) {
    const t = tableMap(table);
    const items = Array.from(t.values());

    const cond = String(keyCondition).trim();
    const isGsi = options.IndexName && options.IndexName !== "" ? true : false;

    let results = [];

    if (isGsi) {
      // Very small emulation: if querying GSI -> expect "<gsi_pk> = :x"
      const [lhs, , rhs] = cond.split(" ");
      const gsiPkName = lhs;
      const val = values[rhs];
      results = items.filter(it => String(it[gsiPkName]) === String(val));
    } else {
      // Primary index: expect "pk = :pk" (simple equality match)
      const [lhs, , rhs] = cond.split(" ");
      const pkName = lhs;
      const val = values[rhs];
      results = items.filter(it => String(it[pkName]) === String(val));
    }

    // Apply Limit (no order guarantee here; tests sort manually where needed)
    if (options.Limit && Number.isInteger(options.Limit)) {
      results = results.slice(0, options.Limit);
    }

    return deepClone(results);
  },

  async deleteItem(table, key) {
    const t = tableMap(table);
    const k = `${key.pk}|${key.sk}`;
    return t.delete(k);
  },
};

function tableMap(name) {
  if (!InMemoryTable.has(name)) InMemoryTable.set(name, new Map());
  return InMemoryTable.get(name);
}

const Logger = {
  writeLog({ flag, action, message, data, critical }) {
    // keep it simple for demo
    console.log(`[LOG][${flag}] ${action} :: ${message}${critical ? " [CRITICAL]" : ""}`, data ? JSON.stringify(data) : "");
  }
};

const ErrorHandler = {
  add_error(message, data) {
    console.error(`[ERROR] ${message}`, data ? JSON.stringify(data) : "");
  }
};

const Formatting = {
  sanitizeValidate(defs) {
    // super light mock to pass values through; enforce "required" presence
    const out = {};
    for (const [k, d] of Object.entries(defs)) {
      const v = d.value ?? d.default ?? null;
      if (d.required && (v === null || v === undefined || v === "")) {
        throw new Error(`Validation failed: ${k} required`);
      }
      out[k] = v;
    }
    return out;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// ShuftiProKyc class (agreed clean version; no exports)
// - CONFIG at bottom of class.configure in the test() call
// - Uses created_at in GSI for time ordering; ALL sorting handled in Node.
// ─────────────────────────────────────────────────────────────────────────────

const crypto = require("crypto");

const KYC_EVENT = {
  REQUEST_PENDING: "request.pending",
  REQUEST_INVALID: "request.invalid",
  REQUEST_UNAUTHORIZED: "request.unauthorized",
  REQUEST_TIMEOUT: "request.timeout",
  REQUEST_DELETED: "request.deleted",
  REQUEST_RECEIVED: "request.received",
  REQUEST_DATA_CHANGED: "request.data.changed",
  VERIFICATION_ACCEPTED: "verification.accepted",
  VERIFICATION_DECLINED: "verification.declined",
  VERIFICATION_STATUS_CHANGED: "verification.status.changed",
  VERIFICATION_CANCELLED: "verification.cancelled",
  REVIEW_PENDING: "review.pending",
};

const ACTIVE_EVENTS = new Set([
  KYC_EVENT.REQUEST_PENDING,
  KYC_EVENT.REQUEST_RECEIVED,
  KYC_EVENT.REVIEW_PENDING,
  KYC_EVENT.VERIFICATION_STATUS_CHANGED,
]);

let CONFIG = {
  TABLE: "kyc_shufti",
  KEYS: {
    pk: "pk",
    sk: "sk",
    gsi_meta: { name: "GSI1", pk: "ppk", sk: "created_at" },
  },
  LOG_FLAGS: {
    request:   "kyc_request",
    webhook:   "kyc_webhook",
    status:    "kyc_status",
    ratelimit: "kyc_rate_limit",
    error:     "kyc_error",
  },
  CLIENT_ID: "",
  SECRET_KEY: "",
  API_URL: "https://api.shuftipro.com/",
  CALLBACK_URL: "",
  REDIRECT_URL: "",
  HTTP_TIMEOUT_MS: 15000,
  DEFAULT_LANGUAGE: "en",
  LOCALE_MAP: {
    en: "en", "en-AU": "en", "en-GB": "en", "en-US": "en",
    zh: "zh", "zh-CN": "zh", "zh-TW": "zh",
    ja: "ja", ko: "ko", tl: "tl",
    fr: "fr", de: "de", es: "es", it: "it", pt: "pt", ru: "ru",
  },
  PER_MINUTE_LIMIT: 60,
  SLACK_WEBHOOK_URL: null,
};

const LOCAL_REQUEST_TIMESTAMPS = [];

class ShuftiProKyc {
  static configure(opts = {}) {
    CONFIG = { ...CONFIG, ...opts };
    if (!/^https?:\/\//i.test(CONFIG.API_URL)) CONFIG.API_URL = "https://api.shuftipro.com/";
    if (!CONFIG.API_URL.endsWith("/")) CONFIG.API_URL += "/";
    Logger.writeLog({
      flag: CONFIG.LOG_FLAGS.request,
      action: "configure",
      message: "KYC configured",
      data: { api: CONFIG.API_URL, callback: !!CONFIG.CALLBACK_URL, table: CONFIG.TABLE }
    });
  }

  static async createVerificationSession({ userId, userEmail, appLocale, userCountry = "", verificationMode = "any", documentConfig = {} }) {
    const clean = Formatting.sanitizeValidate({
      userId:           { value: userId,        type: "string", required: true },
      userEmail:        { value: userEmail,     type: "email",  required: true },
      appLocale:        { value: appLocale ?? null, type: "string", required: false, default: null },
      userCountry:      { value: userCountry ?? "", type: "string", required: false, default: "" },
      verificationMode: { value: verificationMode ?? "any", type: "string", required: false, default: "any" },
    });

    const { pk, sk, gsi_meta } = CONFIG.KEYS;

    // 1) Reuse ACCEPTED or ACTIVE
    const timeline = await ScyllaDb.query(CONFIG.TABLE, `${pk} = :pk`, { ":pk": `user_${clean.userId}` }, { Limit: 50 });
    const sortedTimeline = Array.isArray(timeline) ? timeline.slice().reverse() : [];
    let activeCandidate = null;

    for (const item of sortedTimeline) {
      if (item.type !== "verification_request") continue;

      const byRef = await ScyllaDb.query(
        CONFIG.TABLE,
        `${gsi_meta.pk} = :ref`,
        { ":ref": item.reference },
        { IndexName: gsi_meta.name }
      );
      const latestByRef = Array.isArray(byRef) ? byRef.slice().reverse() : [];
      const meta = pickMeta(latestByRef) || latestByRef[0] || null;

      const status = meta?.status || item.event || "unknown";
      const verificationUrl = meta?.verificationUrl ?? item.verificationUrl ?? null;

      if (status === KYC_EVENT.VERIFICATION_ACCEPTED) {
        Logger.writeLog({ flag: CONFIG.LOG_FLAGS.request, action: "reuse_accepted", message: "Already verified", data: { userId: clean.userId, reference: item.reference } });
        return { alreadyValidated: true, reference: item.reference, status, verificationUrl };
      }
      if (!activeCandidate && ACTIVE_EVENTS.has(status)) {
        activeCandidate = { alreadyHasActive: true, reference: item.reference, status, verificationUrl };
      }
    }

    if (activeCandidate) {
      Logger.writeLog({ flag: CONFIG.LOG_FLAGS.request, action: "reuse_active", message: "Reusing active session", data: { userId: clean.userId, reference: activeCandidate.reference } });
      return activeCandidate;
    }

    // 2) Create NEW
    await registerLocalRateAndMaybeAlert("createVerificationSession");

    const reference  = generateReference();
    const language   = normalizeLocaleToLanguage(clean.appLocale || CONFIG.DEFAULT_LANGUAGE);
    const created_at = new Date().toISOString();

    const payload = {
      reference,
      email: clean.userEmail,
      country: clean.userCountry,
      language,
      verification_mode: clean.verificationMode,
      allow_offline: "1",
      allow_online: "1",
      show_privacy_policy: "0",
      show_results: "1",
      show_consent: "0",
      show_feedback_form: "0",
      manual_review: "0",
      ...(CONFIG.CALLBACK_URL ? { callback_url: CONFIG.CALLBACK_URL } : {}),
      ...(CONFIG.REDIRECT_URL ? { redirect_url: CONFIG.REDIRECT_URL } : {}),
      document: {
        name: documentConfig.name ?? "",
        dob: documentConfig.dob ?? "",
        fetch_enhanced_data: documentConfig.fetch_enhanced_data ?? "1",
        supported_types: documentConfig.supported_types ?? ["id_card", "driving_license", "passport"],
        verification_instructions: {
          allow_paper_based: "1",
          allow_photocopy: "1",
          allow_colorcopy: "1",
          allow_black_and_white: "1",
          allow_laminated: "1",
          allow_screenshot: "1",
          allow_cropped: "1",
          allow_scanned: "1",
          allow_e_document: "1",
          allow_handwritten_document: "1",
          ...(documentConfig.verification_instructions || {}),
        },
      },
    };

    Logger.writeLog({ flag: CONFIG.LOG_FLAGS.request, action: "create_new", message: "Creating Shufti session", data: { userId: clean.userId, reference } });

    const authHeader = "Basic " + Buffer.from(`${CONFIG.CLIENT_ID}:${CONFIG.SECRET_KEY}`, "utf8").toString("base64");
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), CONFIG.HTTP_TIMEOUT_MS);

    let res;
    try {
      res = await fetch(CONFIG.API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": authHeader },
        body: JSON.stringify(payload),
        signal: ctrl.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      ErrorHandler.add_error("KYC network error (createVerificationSession)", { userId: clean.userId, reference, error: String(err) });
      Logger.writeLog({ flag: CONFIG.LOG_FLAGS.error, action: "network_error", message: "Shufti network error", data: { userId: clean.userId, reference }, critical: true });
      throw err;
    }
    clearTimeout(timer);

    const signatureHeader = res.headers.get("signature") || res.headers.get("Signature") || "";
    const rawBody = await res.text();

    let parsed;
    try {
      parsed = rawBody ? JSON.parse(rawBody) : {};
    } catch (e) {
      ErrorHandler.add_error("KYC response invalid JSON", { userId: clean.userId, reference, snippet: rawBody?.slice(0, 500) });
      Logger.writeLog({ flag: CONFIG.LOG_FLAGS.error, action: "invalid_json", message: "Shufti invalid JSON", data: { userId: clean.userId, reference }, critical: true });
      throw e;
    }

    if (!res.ok) {
      ErrorHandler.add_error("KYC response non-200", { userId: clean.userId, reference, status: res.status, parsed });
      Logger.writeLog({ flag: CONFIG.LOG_FLAGS.error, action: "non_200", message: "Shufti non-200", data: { userId: clean.userId, reference, status: res.status } });
    }

    if (!verifyShuftiSignature(rawBody, signatureHeader)) {
      ErrorHandler.add_error("KYC response signature invalid", { userId: clean.userId, reference });
      Logger.writeLog({ flag: CONFIG.LOG_FLAGS.error, action: "invalid_signature", message: "Bad Shufti signature", data: { userId: clean.userId, reference }, critical: true });
      throw new Error("Invalid Shufti HTTP signature");
    }

    const event = parsed?.event || "unknown";
    const verificationUrl = parsed?.verification_url || null;

    await ScyllaDb.putItem(CONFIG.TABLE, {
      [pk]: `user_${clean.userId}`,
      [sk]: created_at,
      [gsi_meta.pk]: reference,
      [gsi_meta.sk]: created_at,
      type: "verification_request",
      userId: clean.userId,
      reference,
      event,
      verificationUrl,
      requestPayload: payload,
      responsePayload: parsed,
      language,
      created_at,
    });

    await ScyllaDb.putItem(CONFIG.TABLE, {
      [pk]: `meta_${reference}`,
      [sk]: "meta",
      [gsi_meta.pk]: reference,
      [gsi_meta.sk]: created_at,
      type: "meta",
      userId: clean.userId,
      reference,
      status: event,
      verificationUrl,
      language,
      created_at,
    });

    Logger.writeLog({ flag: CONFIG.LOG_FLAGS.request, action: "created", message: "Shufti session created", data: { userId: clean.userId, reference, event } });

    return { reference, verificationUrl };
  }

  static async handleWebhook({ rawBodyString, signatureHeader }) {
    Logger.writeLog({ flag: CONFIG.LOG_FLAGS.webhook, action: "received", message: "Webhook received", data: { bytes: rawBodyString ? String(rawBodyString).length : 0 } });

    if (!verifyShuftiSignature(rawBodyString, signatureHeader)) {
      ErrorHandler.add_error("KYC webhook signature invalid");
      Logger.writeLog({ flag: CONFIG.LOG_FLAGS.error, action: "invalid_signature", message: "Webhook bad signature", data: {}, critical: true });
      return { ok: false };
    }

    let payload;
    try {
      payload = JSON.parse(rawBodyString);
    } catch {
      ErrorHandler.add_error("KYC webhook invalid JSON", { snippet: String(rawBodyString).slice(0, 500) });
      Logger.writeLog({ flag: CONFIG.LOG_FLAGS.error, action: "invalid_json", message: "Webhook invalid JSON", data: {}, critical: true });
      return { ok: false };
    }

    const reference = payload?.reference || "unknown";
    const event = payload?.event || "unknown";
    const created_at = new Date().toISOString();

    const { pk, sk, gsi_meta } = CONFIG.KEYS;

    const byRef = await ScyllaDb.query(CONFIG.TABLE, `${gsi_meta.pk} = :ref`, { ":ref": reference }, { IndexName: gsi_meta.name });
    const latestByRef = Array.isArray(byRef) ? byRef.slice().reverse() : [];
    const meta = pickMeta(latestByRef) || latestByRef[0] || null;
    const userId = meta?.userId || payload?.user_id || "unknown";

    await ScyllaDb.putItem(CONFIG.TABLE, {
      [pk]: `user_${userId}`,
      [sk]: created_at,
      [gsi_meta.pk]: reference,
      [gsi_meta.sk]: created_at,
      type: "webhook_event",
      userId,
      reference,
      event,
      webhookPayload: payload,
      created_at,
    });

    await ScyllaDb.putItem(CONFIG.TABLE, {
      [pk]: `meta_${reference}`,
      [sk]: "meta",
      [gsi_meta.pk]: reference,
      [gsi_meta.sk]: created_at,
      type: "meta",
      userId,
      reference,
      status: event,
      lastEvent: event,
      lastEventAt: created_at,
      verificationUrl: meta?.verificationUrl ?? null,
      language: meta?.language ?? CONFIG.DEFAULT_LANGUAGE,
      created_at: meta?.created_at ?? created_at,
    });

    Logger.writeLog({ flag: CONFIG.LOG_FLAGS.webhook, action: "stored", message: "Webhook stored + meta updated", data: { userId, reference, event } });

    return { ok: true, reference, event };
  }

  static async getRecordByReference(reference) {
    const { pk, sk, gsi_meta } = CONFIG.KEYS;
    const items = await ScyllaDb.query(CONFIG.TABLE, `${gsi_meta.pk} = :ref`, { ":ref": reference }, { IndexName: gsi_meta.name });
    if (!Array.isArray(items) || !items.length) return null;

    const sorted = items.slice().reverse();

    let meta = null;
    const verificationRequests = [];
    const webhookEvents = [];
    const statusChanges = [];

    for (const item of sorted) {
      if (item.type === "meta") meta = item;
      else if (item.type === "verification_request") verificationRequests.push(item);
      else if (item.type === "webhook_event") webhookEvents.push(item);
      else if (item.type === "status_change") statusChanges.push(item);
    }

    if (!meta) {
      meta = await ScyllaDb.getItem(CONFIG.TABLE, { [pk]: `meta_${reference}`, [sk]: "meta" });
    }
    return { meta, verificationRequests, webhookEvents, statusChanges };
  }

  static async isUserValidated(userId) {
    const { pk, gsi_meta } = CONFIG.KEYS;

    const timeline = await ScyllaDb.query(CONFIG.TABLE, `${pk} = :pk`, { ":pk": `user_${userId}` }, { Limit: 50 });
    if (!Array.isArray(timeline) || !timeline.length) return false;

    const sortedTimeline = timeline.slice().reverse();
    for (const item of sortedTimeline) {
      if (item.type !== "verification_request") continue;

      const byRef = await ScyllaDb.query(CONFIG.TABLE, `${gsi_meta.pk} = :ref`, { ":ref": item.reference }, { IndexName: gsi_meta.name });
      const latestByRef = Array.isArray(byRef) ? byRef.slice().reverse() : [];
      const meta = pickMeta(latestByRef) || latestByRef[0] || null;

      if (meta?.status === KYC_EVENT.VERIFICATION_ACCEPTED) return true;
    }
    return false;
  }

  static async updateRecordStatus(reference, newStatus) {
    const { pk, sk, gsi_meta } = CONFIG.KEYS;

    const byRef = await ScyllaDb.query(CONFIG.TABLE, `${gsi_meta.pk} = :ref`, { ":ref": reference }, { IndexName: gsi_meta.name });
    const latestByRef = Array.isArray(byRef) ? byRef.slice().reverse() : [];
    let meta = pickMeta(latestByRef) || latestByRef[0] || null;

    if (!meta) {
      meta = await ScyllaDb.getItem(CONFIG.TABLE, { [pk]: `meta_${reference}`, [sk]: "meta" });
    }
    if (!meta) {
      ErrorHandler.add_error("KYC updateRecordStatus: meta not found", { reference, newStatus });
      Logger.writeLog({ flag: CONFIG.LOG_FLAGS.error, action: "meta_missing", message: "Meta not found", data: { reference, newStatus } });
      return false;
    }

    const created_at = new Date().toISOString();

    await ScyllaDb.putItem(CONFIG.TABLE, {
      [pk]: `meta_${reference}`,
      [sk]: "meta",
      [gsi_meta.pk]: reference,
      [gsi_meta.sk]: created_at,
      type: "meta",
      userId: meta.userId,
      reference,
      status: newStatus,
      lastEvent: newStatus,
      lastEventAt: created_at,
      verificationUrl: meta.verificationUrl ?? null,
      language: meta.language ?? CONFIG.DEFAULT_LANGUAGE,
      created_at: meta.created_at ?? created_at,
    });

    await ScyllaDb.putItem(CONFIG.TABLE, {
      [pk]: `user_${meta.userId}`,
      [sk]: created_at,
      [gsi_meta.pk]: reference,
      [gsi_meta.sk]: created_at,
      type: "status_change",
      userId: meta.userId,
      reference,
      event: KYC_EVENT.VERIFICATION_STATUS_CHANGED,
      newStatus,
      created_at,
    });

    Logger.writeLog({ flag: CONFIG.LOG_FLAGS.status, action: "updated", message: "Status updated", data: { reference, newStatus, userId: meta.userId } });
    return true;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers used by the class
// ─────────────────────────────────────────────────────────────────────────────

function generateReference() {
  return `ref-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
}
function normalizeLocaleToLanguage(appLocale) {
  if (!appLocale) return CONFIG.DEFAULT_LANGUAGE;
  const key = String(appLocale).trim();
  return CONFIG.LOCALE_MAP[key] || CONFIG.LOCALE_MAP[key.split("-")[0]] || CONFIG.DEFAULT_LANGUAGE;
}
function verifyShuftiSignature(rawBodyString, signatureHeaderValue) {
  if (!rawBodyString || !signatureHeaderValue) return false;
  const inner = crypto.createHash("sha256").update(CONFIG.SECRET_KEY, "utf8").digest("hex");
  const computed = crypto.createHash("sha256").update(String(rawBodyString) + inner, "utf8").digest("hex");
  return computed === String(signatureHeaderValue).trim();
}

// prefer the “meta” row from a list if present
function pickMeta(items) {
  if (!Array.isArray(items)) return null;
  for (const it of items) if (it.type === "meta") return it;
  return null;
}

// Local naive rate-limiter alert
async function registerLocalRateAndMaybeAlert(contextLabel) {
  const now = Date.now();
  LOCAL_REQUEST_TIMESTAMPS.push(now);
  while (LOCAL_REQUEST_TIMESTAMPS.length && now - LOCAL_REQUEST_TIMESTAMPS[0] > 60000) {
    LOCAL_REQUEST_TIMESTAMPS.shift();
  }
  const count = LOCAL_REQUEST_TIMESTAMPS.length;
  if (count > CONFIG.PER_MINUTE_LIMIT) {
    Logger.writeLog({
      flag: CONFIG.LOG_FLAGS.ratelimit,
      action: "breach",
      message: "Local per-minute threshold breached",
      data: { contextLabel, count },
      critical: true
    });
    // Persist a system row for visibility
    await ScyllaDb.putItem(CONFIG.TABLE, {
      pk: "system_shufti",
      sk: new Date().toISOString(),
      ppk: "rate_limit",
      created_at: new Date().toISOString(),
      type: "rate_limit",
      context: contextLabel,
      countInLastMinute: count,
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock “fetch” (Shufti API) with multiple scenarios controlled by a global mode
// ─────────────────────────────────────────────────────────────────────────────

const FetchMode = {
  HAPPY: "HAPPY",
  NON_200: "NON_200",
  INVALID_JSON: "INVALID_JSON",
  BAD_SIGNATURE: "BAD_SIGNATURE",
  NETWORK_ERROR: "NETWORK_ERROR",
};

let CURRENT_FETCH_MODE = FetchMode.HAPPY;

global.fetch = async function(url, options) {
  // simulate network error
  if (CURRENT_FETCH_MODE === FetchMode.NETWORK_ERROR) {
    throw new Error("Simulated network failure");
  }

  // accept only POST for this mock
  const body = options?.body || "{}";
  const req = JSON.parse(body);
  const base = {
    reference: req.reference,
    event: KYC_EVENT.REQUEST_PENDING,
    verification_url: `https://verify.example/${req.reference}`,
  };

  // shape the response body & signature
  let rawBody;
  let status = 200;

  switch (CURRENT_FETCH_MODE) {
    case FetchMode.NON_200:
      status = 400;
      rawBody = JSON.stringify({ event: KYC_EVENT.REQUEST_INVALID, error: "Bad request" });
      break;
    case FetchMode.INVALID_JSON:
      status = 200;
      rawBody = "{ not-json";
      break;
    default: // HAPPY + BAD_SIGNATURE both still send a JSON body
      status = 200;
      rawBody = JSON.stringify(base);
      break;
  }

  // compute signature (except for BAD_SIGNATURE which returns wrong one)
  const inner = crypto.createHash("sha256").update(CONFIG.SECRET_KEY, "utf8").digest("hex");
  const goodSig = crypto.createHash("sha256").update(String(rawBody) + inner, "utf8").digest("hex");
  const signature = (CURRENT_FETCH_MODE === FetchMode.BAD_SIGNATURE) ? "WRONG" : goodSig;

  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Map([["signature", signature]]),
    text: async () => rawBody,
    // emulate Headers.get
    headers: {
      get: (k) => (k.toLowerCase() === "signature" ? signature : null),
    },
  };
};

// ─────────────────────────────────────────────────────────────────────────────
// Test runner exercising all scenarios & edge cases
// ─────────────────────────────────────────────────────────────────────────────

async function test() {
  // Configure the class
  ShuftiProKyc.configure({
    CLIENT_ID: "client_123",
    SECRET_KEY: "secret_abc",
    API_URL: "https://mock.shufti/api",
    CALLBACK_URL: "https://your.app/kyc/webhook",
    REDIRECT_URL: "https://your.app/kyc/status",
    TABLE: "kyc_shufti",
  });

  const userId = "u1";
  const userEmail = "user@example.com";

  // 1) Happy path: create a new session
  CURRENT_FETCH_MODE = FetchMode.HAPPY;
  const { reference, verificationUrl } = await ShuftiProKyc.createVerificationSession({
    userId, userEmail, appLocale: "en-AU", userCountry: "AU", verificationMode: "any",
    documentConfig: { name: "John Doe", dob: "1990-01-01" }
  });
  console.log("NEW SESSION:", { reference, verificationUrl });

  // 2) Try to create again: should reuse ACTIVE (request.pending)
  const reuseActive = await ShuftiProKyc.createVerificationSession({
    userId, userEmail, appLocale: "en-AU", userCountry: "AU"
  });
  console.log("REUSE ACTIVE:", reuseActive);

  // 3) Webhook accepted
  {
    const acceptedPayload = JSON.stringify({ reference, event: KYC_EVENT.VERIFICATION_ACCEPTED });
    const sig = signatureFor(acceptedPayload, "secret_abc");
    const webhookRes = await ShuftiProKyc.handleWebhook({ rawBodyString: acceptedPayload, signatureHeader: sig });
    console.log("WEBHOOK ACCEPTED:", webhookRes);
  }

  // 4) After accepted, creating again should return alreadyValidated
  const reuseValidated = await ShuftiProKyc.createVerificationSession({
    userId, userEmail
  });
  console.log("REUSE VALIDATED:", reuseValidated);

  // 5) Non-200 response still logs error, returns reference (since we store attempt anyway)
  CURRENT_FETCH_MODE = FetchMode.NON_200;
  const non200 = await ShuftiProKyc.createVerificationSession({
    userId, userEmail
  });
  console.log("NON-200 CREATE:", non200);

  // 6) Invalid JSON response → throws
  CURRENT_FETCH_MODE = FetchMode.INVALID_JSON;
  try {
    await ShuftiProKyc.createVerificationSession({ userId, userEmail });
  } catch (e) {
    console.log("INVALID JSON CREATE (caught):", e.message);
  }

  // 7) Bad signature response → throws
  CURRENT_FETCH_MODE = FetchMode.BAD_SIGNATURE;
  try {
    await ShuftiProKyc.createVerificationSession({ userId, userEmail });
  } catch (e) {
    console.log("BAD SIGNATURE CREATE (caught):", e.message);
  }

  // 8) Network error → throws
  CURRENT_FETCH_MODE = FetchMode.NETWORK_ERROR;
  try {
    await ShuftiProKyc.createVerificationSession({ userId, userEmail });
  } catch (e) {
    console.log("NETWORK ERROR CREATE (caught):", e.message);
  }

  // Reset to HAPPY for webhook tests
  CURRENT_FETCH_MODE = FetchMode.HAPPY;

  // 9) Webhook invalid signature
  {
    const body = JSON.stringify({ reference, event: KYC_EVENT.VERIFICATION_DECLINED });
    const badSig = "WRONG";
    const wb = await ShuftiProKyc.handleWebhook({ rawBodyString: body, signatureHeader: badSig });
    console.log("WEBHOOK BAD SIG:", wb);
  }

  // 10) Webhook invalid JSON
  {
    const wb = await ShuftiProKyc.handleWebhook({ rawBodyString: "{ nope", signatureHeader: "whatever" });
    console.log("WEBHOOK BAD JSON:", wb);
  }

  // 11) Manual status update for NON-EXISTENT ref → false
  const statusFalse = await ShuftiProKyc.updateRecordStatus("ref-does-not-exist", KYC_EVENT.VERIFICATION_ACCEPTED);
  console.log("UPDATE STATUS (missing meta):", statusFalse);

  // 12) Rate limit: spam > PER_MINUTE_LIMIT
  for (let i = 0; i < CONFIG.PER_MINUTE_LIMIT + 5; i++) {
    try {
      await ShuftiProKyc.createVerificationSession({ userId: "flood", userEmail: "flood@example.com" });
    } catch { /* ignore failures here */ }
  }
  console.log("RATE LIMIT test completed (check logs & DB rows)");

  // Final: pull a full record by reference
  const fullRecord = await ShuftiProKyc.getRecordByReference(reference);
  console.log("FULL RECORD (by reference):", !!fullRecord, { keys: Object.keys(fullRecord || {}) });

  // isUserValidated checks
  const isVal = await ShuftiProKyc.isUserValidated(userId);
  console.log("isUserValidated:", isVal);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tiny helpers for the harness
// ─────────────────────────────────────────────────────────────────────────────

function signatureFor(raw, secret) {
  const inner = crypto.createHash("sha256").update(secret, "utf8").digest("hex");
  return crypto.createHash("sha256").update(String(raw) + inner, "utf8").digest("hex");
}

function deepClone(o) {
  return JSON.parse(JSON.stringify(o));
}

// Run the tests
test().catch(err => {
  console.error("TEST RUN FAILED:", err);
  process.exit(1);
});
Jest test plan (titles you can drop straight into describe/test)
Configuration

loads default CONFIG and applies overrides via configure()

normalizes API URL to include trailing slash

Session creation (happy path)

creates a new session, stores verification_request + meta rows

returns { reference, verificationUrl }

logs with Logger.writeLog (flag kyc_request, action created)

Session reuse

when prior attempt status is verification.accepted → returns { alreadyValidated: true, ... }

when prior attempt status is ACTIVE (request.pending, etc.) → returns { alreadyHasActive: true, ... }

Webhook handling

valid signature + valid JSON → stores webhook_event, updates meta.status

invalid signature → returns { ok:false }, logs error, does not write webhook_event

invalid JSON → returns { ok:false }, logs error, does not write webhook_event

isUserValidated

returns true if any reference meta has verification.accepted

returns false otherwise

updateRecordStatus

returns false and logs error when meta missing

updates meta.status and appends status_change row when meta exists

HTTP error paths

NON-200 response → logs via ErrorHandler + Logger, still writes request attempt row

invalid JSON → throws and logs via ErrorHandler + Logger

bad signature → throws and logs via ErrorHandler + Logger

network error → throws and logs via ErrorHandler + Logger

Rate limiting

after > PER_MINUTE_LIMIT attempts in 60s → writes rate_limit system row and logs with kyc_rate_limit
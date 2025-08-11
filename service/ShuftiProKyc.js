import { SafeUtils, ScyllaDb, ErrorHandler, Logger } from "../utils/index.js";
const crypto = require("crypto");

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
    request: "kyc_request",
    webhook: "kyc_webhook",
    status: "kyc_status",
    ratelimit: "kyc_rate_limit",
    error: "kyc_error",
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
    en: "en",
    "en-AU": "en",
    "en-GB": "en",
    "en-US": "en",
    zh: "zh",
    "zh-CN": "zh",
    "zh-TW": "zh",
    ja: "ja",
    ko: "ko",
    tl: "tl",
    fr: "fr",
    de: "de",
    es: "es",
    it: "it",
    pt: "pt",
    ru: "ru",
  },

  // Local (client-side) rate alert
  PER_MINUTE_LIMIT: 60,
  SLACK_WEBHOOK_URL: null,
};

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

const LOCAL_REQUEST_TIMESTAMPS = [];

export default class ShuftiProKyc {
  static configure(options = {}) {
    CONFIG = { ...CONFIG, ...options };
    if (!/^https?:\/\//i.test(CONFIG.API_URL))
      CONFIG.API_URL = "https://api.shuftipro.com/";
    if (!CONFIG.API_URL.endsWith("/")) CONFIG.API_URL += "/";
    Logger.writeLog({
      flag: CONFIG.LOG_FLAGS.request,
      action: "configure",
      message: "KYC configured",
      data: {
        api: CONFIG.API_URL,
        callback: !!CONFIG.CALLBACK_URL,
        table: CONFIG.TABLE,
      },
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
    const clean = SafeUtils.sanitizeValidate({
      userId: { value: userId, type: "string", required: true },
      userEmail: { value: userEmail, type: "email", required: true },
      appLocale: {
        value: appLocale ?? null,
        type: "string",
        required: false,
        default: null,
      },
      userCountry: {
        value: userCountry ?? "",
        type: "string",
        required: false,
        default: "",
      },
      verificationMode: {
        value: verificationMode ?? "any",
        type: "string",
        required: false,
        default: "any",
      },
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

    const sortedTimeline = Array.isArray(timeline)
      ? timeline.slice().reverse()
      : []; // newest last? normalize by reversing
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
      const verificationUrl =
        meta?.verificationUrl ?? item.verificationUrl ?? null;

      if (status === KYC_EVENT.VERIFICATION_ACCEPTED) {
        Logger.writeLog({
          flag: CONFIG.LOG_FLAGS.request,
          action: "reuse_accepted",
          message: "User already verified; returning accepted session",
          data: { userId: clean.userId, reference: item.reference },
        });
        return {
          alreadyValidated: true,
          reference: item.reference,
          status,
          verificationUrl,
        };
      }
      if (!activeCandidate && ACTIVE_EVENTS.has(status)) {
        activeCandidate = {
          alreadyHasActive: true,
          reference: item.reference,
          status,
          verificationUrl,
        };
      }
    }

    if (activeCandidate) {
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.request,
        action: "reuse_active",
        message: "Active verification session exists; reusing",
        data: {
          userId: clean.userId,
          reference: activeCandidate.reference,
          status: activeCandidate.status,
        },
      });
      return activeCandidate;
    }

    // 2) CREATE a new session
    await registerLocalRateAndMaybeAlert("createVerificationSession");

    const reference = generateReference();
    const language = normalizeLocaleToLanguage(
      clean.appLocale || CONFIG.DEFAULT_LANGUAGE
    );
    const created_at = new Date().toISOString();

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
        supported_types: documentConfig.supported_types ?? [
          "id_card",
          "driving_license",
          "passport",
        ],
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
      data: { userId: clean.userId, reference },
    });

    // HTTP to Shufti (Basic auth)
    const authHeader =
      "Basic " +
      Buffer.from(`${CONFIG.CLIENT_ID}:${CONFIG.SECRET_KEY}`, "utf8").toString(
        "base64"
      );
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), CONFIG.HTTP_TIMEOUT_MS);

    let res;
    try {
      res = await fetch(CONFIG.API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: authHeader,
        },
        body: JSON.stringify(payload),
        signal: ctrl.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      ErrorHandler.add_error("KYC network error (createVerificationSession)", {
        userId: clean.userId,
        reference,
        error: String(err),
      });
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "network_error",
        message: "Network error contacting Shufti",
        data: { userId: clean.userId, reference, error: String(err) },
        critical: true,
      });
      throw err;
    }
    clearTimeout(timer);

    const signatureHeader =
      res.headers.get("signature") || res.headers.get("Signature") || "";
    const rawBody = await res.text();

    let parsed;
    try {
      parsed = rawBody ? JSON.parse(rawBody) : {};
    } catch (e) {
      ErrorHandler.add_error("KYC response invalid JSON", {
        userId: clean.userId,
        reference,
        snippet: rawBody?.slice(0, 500),
      });
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "invalid_json",
        message: "Shufti returned invalid JSON",
        data: { userId: clean.userId, reference },
        critical: true,
      });
      throw e;
    }

    if (!res.ok) {
      // Not fatal for flow, but is an error condition to record
      ErrorHandler.add_error("KYC response non-200", {
        userId: clean.userId,
        reference,
        status: res.status,
        parsed,
      });
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "non_200",
        message: "Shufti returned non-200",
        data: { userId: clean.userId, reference, status: res.status },
      });
    }

    if (!verifyShuftiSignature(rawBody, signatureHeader)) {
      ErrorHandler.add_error("KYC response signature invalid", {
        userId: clean.userId,
        reference,
      });
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "invalid_signature",
        message: "Invalid signature in Shufti response",
        data: { userId: clean.userId, reference },
        critical: true,
      });
      throw new Error("Invalid Shufti HTTP signature");
    }

    const event = parsed?.event || "unknown";
    const verificationUrl = parsed?.verification_url || null;

    // Persist attempt on user timeline
    await ScyllaDb.putItem(CONFIG.TABLE, {
      [pk]: `user_${clean.userId}`,
      [sk]: created_at, // natural ISO sort
      [gsi_meta.pk]: reference,
      [gsi_meta.sk]: created_at, // GSI sort = created_at
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
      [gsi_meta.sk]: created_at, // keep meta time-aligned for timeline purposes
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
      data: { userId: clean.userId, reference, event },
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
      data: { bytes: rawBodyString ? String(rawBodyString).length : 0 },
    });

    if (!verifyShuftiSignature(rawBodyString, signatureHeader)) {
      ErrorHandler.add_error("KYC webhook signature invalid");
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "invalid_signature",
        message: "Invalid signature on webhook",
        data: {},
        critical: true,
      });
      return { ok: false };
    }

    let payload;
    try {
      payload = JSON.parse(rawBodyString);
    } catch {
      ErrorHandler.add_error("KYC webhook invalid JSON", {
        snippet: String(rawBodyString).slice(0, 500),
      });
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "invalid_json",
        message: "Webhook JSON parse failed",
        data: {},
        critical: true,
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
      data: { userId, reference, event },
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
      else if (item.type === "verification_request")
        verificationRequests.push(item);
      else if (item.type === "webhook_event") webhookEvents.push(item);
      else if (item.type === "status_change") statusChanges.push(item);
    }

    if (!meta) {
      // Fallback direct get if meta wasn’t present in GSI scan (shouldn’t happen, but safe)
      meta = await ScyllaDb.getItem(CONFIG.TABLE, {
        [pk]: `meta_${reference}`,
        [sk]: "meta",
      });
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
      meta = await ScyllaDb.getItem(CONFIG.TABLE, {
        [pk]: `meta_${reference}`,
        [sk]: "meta",
      });
    }
    if (!meta) {
      ErrorHandler.add_error("KYC updateRecordStatus: meta not found", {
        reference,
        newStatus,
      });
      Logger.writeLog({
        flag: CONFIG.LOG_FLAGS.error,
        action: "meta_missing",
        message: "Meta not found for reference during status update",
        data: { reference, newStatus },
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
      data: { reference, newStatus, userId: meta.userId },
    });

    return true;
  }
}

function generateReference() {
  return `ref-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
}
function normalizeLocaleToLanguage(appLocale) {
  if (!appLocale) return CONFIG.DEFAULT_LANGUAGE;
  const key = String(appLocale).trim();
  return (
    CONFIG.LOCALE_MAP[key] ||
    CONFIG.LOCALE_MAP[key.split("-")[0]] ||
    CONFIG.DEFAULT_LANGUAGE
  );
}
function verifyShuftiSignature(rawBodyString, signatureHeaderValue) {
  if (!rawBodyString || !signatureHeaderValue) return false;
  const inner = crypto
    .createHash("sha256")
    .update(CONFIG.SECRET_KEY, "utf8")
    .digest("hex");
  const computed = crypto
    .createHash("sha256")
    .update(String(rawBodyString) + inner, "utf8")
    .digest("hex");
  return computed === String(signatureHeaderValue).trim();
}
// prefer the “meta” row if it exists in a list
function pickMeta(items) {
  if (!Array.isArray(items)) return null;
  for (const it of items) if (it.type === "meta") return it;
  return null;
}

// Local naive rate-limiter alert
async function registerLocalRateAndMaybeAlert(contextLabel) {
  const now = Date.now();
  LOCAL_REQUEST_TIMESTAMPS.push(now);
  while (
    LOCAL_REQUEST_TIMESTAMPS.length &&
    now - LOCAL_REQUEST_TIMESTAMPS[0] > 60000
  ) {
    LOCAL_REQUEST_TIMESTAMPS.shift();
  }
  const count = LOCAL_REQUEST_TIMESTAMPS.length;
  if (count > CONFIG.PER_MINUTE_LIMIT) {
    Logger.writeLog({
      flag: CONFIG.LOG_FLAGS.ratelimit,
      action: "breach",
      message: "Local per-minute threshold breached",
      data: { contextLabel, count },
      critical: true,
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

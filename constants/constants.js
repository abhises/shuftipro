// kycEvents.js

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

const FetchMode = {
  HAPPY: "HAPPY",
  NON_200: "NON_200",
  INVALID_JSON: "INVALID_JSON",
  BAD_SIGNATURE: "BAD_SIGNATURE",
  NETWORK_ERROR: "NETWORK_ERROR",
};

const CONFIG = {
  TABLE: "kyc_shufti",
  KEYS: {
    pk: "pk",
    sk: "sk",
    gsi_meta: { name: "GSI1", pk: "ppk", sk: "created_at" },
  },
  LOG_FLAGS: {
    request: "kyc_request",
    webhook: "kyc_webhook",
    status: "kyc_status",
    ratelimit: "kyc_rate_limit",
    error: "kyc_error",
  },
  CLIENT_ID: process.env.KYC_CLIENT_ID || "",
  SECRET_KEY: process.env.KYC_SECRET_KEY || "",
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
  PER_MINUTE_LIMIT: 60,
  SLACK_WEBHOOK_URL: null,
};

export { KYC_EVENT, FetchMode, CONFIG };

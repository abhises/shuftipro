export default class SafeUtils {
  /**
   * Check whether a value should be considered “present”.
   * Mirrors behaviour of PHP::has_value():
   *   • null / undefined      → false
   *   • empty / whitespace "" → false
   *   • NaN                   → false
   *   • []                    → false
   *   • {}                    → false
   *   • everything else       → true
   *
   * @param {*} value
   * @returns {boolean}
   */
  static hasValue(value) {
    // Fast null/undefined exit
    if (value === null || value === undefined) return false;

    // String: ignore pure-whitespace
    if (typeof value === "string") return value.trim().length > 0;

    // Number: reject NaN (0 is allowed)
    if (typeof value === "number") return !Number.isNaN(value);

    // Array: at least one element
    if (Array.isArray(value)) return value.length > 0;

    // Object: at least one own enumerable key
    if (typeof value === "object") return Object.keys(value).length > 0;

    // Boolean, bigint, symbol, function → treat as “has value”
    return true;
  }

  static sanitizeValidate(args = {}) {
    // Helper to detect plain objects
    const isPlainObject = (obj) =>
      obj !== null &&
      typeof obj === "object" &&
      !Array.isArray(obj) &&
      Object.getPrototypeOf(obj) === Object.prototype;

    if (!isPlainObject(args)) {
      throw new TypeError("sanitizeValidate(): args must be a plain object");
    }

    const sanitizers = {
      int: SafeUtils.sanitizeInteger,
      integer: SafeUtils.sanitizeInteger,
      float: SafeUtils.sanitizeFloat,
      numeric: SafeUtils.sanitizeFloat,
      bool: SafeUtils.sanitizeBoolean,
      boolean: SafeUtils.sanitizeBoolean,
      string: SafeUtils.sanitizeTextField,
      text: SafeUtils.sanitizeTextField,
      array: SafeUtils.sanitizeArray,
      iterable: SafeUtils.sanitizeIterable,
      email: SafeUtils.sanitizeEmail,
      url: SafeUtils.sanitizeUrl,
      html: SafeUtils.sanitizeHtmlWithWhitelist,
      object: SafeUtils.sanitizeObject, // ✅ Add this line
    };

    const result = {};

    for (const [key, rule] of Object.entries(args)) {
      if (!isPlainObject(rule) || typeof rule.type !== "string") {
        throw new TypeError(`sanitizeValidate(): invalid schema for "${key}"`);
      }

      const { value, type, required = false, default: defaultValue } = rule;

      const sanitizer = sanitizers[type.toLowerCase()];
      if (typeof sanitizer !== "function") {
        throw new TypeError(
          `sanitizeValidate(): unknown type "${type}" for "${key}"`
        );
      }

      // Check presence
      if (!required && !SafeUtils.hasValue(value)) {
        // not required + missing → default or null
        result[key] = "default" in rule ? defaultValue : null;
        continue;
      }

      if (required && !SafeUtils.hasValue(value)) {
        throw new TypeError(`Missing required parameter: ${key}`);
      }

      // Attempt sanitization
      const cleaned = sanitizer(value);
      if (cleaned === null) {
        throw new TypeError(`Invalid type for "${key}". Expected ${type}.`);
      }

      result[key] = cleaned;
    }

    return result;
  }

  static sanitizeUrl(val) {
    // 1. Only strings
    if (typeof val !== "string") return null;
    const input = val.trim();

    try {
      // 2. Parse using native URL
      const url = new URL(input);

      // 3. Only allow http(s) and max 2048 characters
      if (
        (url.protocol !== "http:" && url.protocol !== "https:") ||
        url.href.length > 2048
      ) {
        return null;
      }

      // 6. Return normalized href
      return url.href;
    } catch {
      // invalid URL
      return null;
    }
  }

  static sanitizeTextField(val) {
    // 1. Only accept real strings
    if (typeof val !== "string") return null;

    // 2. Trim first to avoid wasted work on pure‐whitespace
    let str = val.trim();
    if (!str) return null;

    // 3. Strip HTML tags, control & formatting chars in one pass:
    //    - <\/?[^>]+(>|$)         → any simple HTML tag
    //    - [\p{C}]                → any Unicode "Other" category (control/formatting)
    //    (note the 'u' flag for Unicode escapes, 'g' for global)
    str = str.replace(/<\/?[^>]+(>|$)|[\p{C}]/gu, "").trim();

    // 4. Return non-empty or null
    return str.length > 0 ? str : null;
  }

  static escUrl(rawUrl, allowedProtocols = ["http:", "https:", "ftp:"]) {
    // 1. Must be a non-empty string
    if (typeof rawUrl !== "string") return "";
    const input = rawUrl.trim();
    if (input === "") return "";

    // 2. Is it relative? (starts with "/" or "./" or "../")
    const isRelative = /^[\/.]/.test(input);

    let url;
    try {
      // 3. Parse with a dummy base so relative URLs work
      url = new URL(input, "http://dummy.local");
    } catch {
      return ""; // invalid URL syntax
    }

    // 4. Enforce protocol whitelist (normalize to lower case)
    const proto = url.protocol.toLowerCase();
    if (!allowedProtocols.map((p) => p.toLowerCase()).includes(proto)) {
      return "";
    }

    // 5. Strip out any embedded credentials
    url.username = "";
    url.password = "";

    // 6. Re-encode each path segment safely
    const cleanPath = url.pathname
      .split("/")
      .map((seg) => {
        try {
          // decode first (in case it’s already percent-encoded),
          // then re-encode everything that needs it
          return encodeURIComponent(decodeURIComponent(seg));
        } catch {
          // if decodeURIComponent throws, just encode the raw segment
          return encodeURIComponent(seg);
        }
      })
      .join("/");

    // 7. Serialize query & fragment
    const cleanSearch = url.search
      ? "?" + new URLSearchParams(url.searchParams).toString()
      : "";
    const cleanHash = url.hash; // URL class auto-encodes hash

    // 8. Return relative or absolute form
    if (isRelative) {
      return `${cleanPath}${cleanSearch}${cleanHash}`;
    } else {
      // url.host includes hostname + port
      return `${url.protocol}//${url.host}${cleanPath}${cleanSearch}${cleanHash}`;
    }
  }

  /**
   * Ensures input is an array and strips empty/null/undefined items.
   * Optional: could accept inner item sanitizer (not yet needed).
   *
   * @param {*} input
   * @returns {Array}
   */
  static sanitizeArray(input) {
    // 1. Nullish → empty array
    if (input == null) return [];

    // 2. Wrap non-arrays into an array
    const arr = Array.isArray(input) ? input : [input];

    // 3. Filter out any “empty” values using your hasValue
    //    Passing the method reference directly ignores extra args.
    return arr.filter(SafeUtils.hasValue);
  }

  // Individual atomic sanitisers below...

  /**
   * Trim whitespace, preserve 0/false, and optionally escape HTML.
   *
   * @param {*} val           Any value you want as a string
   * @param {boolean} escape  If true, HTML-escape &<>"'
   * @returns {string}        A trimmed, safe string
   */
  static sanitizeString(val = "", escape = false) {
    // 1. Always get a string (undefined → '', null → 'null')
    let s = typeof val === "string" ? val : String(val);

    // 2. Trim once
    s = s.trim();

    // 3. Optionally escape HTML if you really need “sanitize”
    if (escape) {
      s = s.replace(
        /[&<>"']/g,
        (chr) =>
          ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;",
          }[chr])
      );
    }

    return s;
  }

  static sanitizeInteger(val) {
    // 1. Nullish → no integer
    if (val == null) return null;

    // 2. If it’s already a number, ensure it’s an integer and in the safe range
    if (typeof val === "number") {
      return Number.isInteger(val) && Number.isSafeInteger(val) ? val : null;
    }

    // 3. If it’s a string, trim and validate strictly as a base-10 integer
    if (typeof val === "string") {
      const str = val.trim();
      // Reject anything that isn’t an optional +/- followed by digits
      if (!/^[+-]?\d+$/.test(str)) {
        return null;
      }
      const n = Number(str);
      // Finally, ensure it’s within safe integer bounds
      return Number.isSafeInteger(n) ? n : null;
    }

    // 4. Everything else → not an integer
    return null;
  }

  static sanitizeFloat(val) {
    // 1. Nullish → no value
    if (val == null) return null;

    // 2. If it’s already a number, ensure it’s finite
    if (typeof val === "number") {
      return Number.isFinite(val) ? val : null;
    }

    // 3. If it’s a string, trim and validate strictly
    if (typeof val === "string") {
      const str = val.trim();

      // Strict float pattern:
      //  • Optional sign
      //  • Digits with optional decimal, or just decimal+digits
      //  • Optional exponent part
      const floatPattern = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/;
      if (!floatPattern.test(str)) {
        return null;
      }

      const n = Number(str);
      // Reject NaN, ±Infinity
      return Number.isFinite(n) ? n : null;
    }

    // 4. Everything else → not a float
    return null;
  }

  static sanitizeBoolean(val) {
    // Define your truthy/falsy lookups locally
    const TRUE_VALUES = new Set(["1", "true", "yes", "y", "on"]);
    const FALSE_VALUES = new Set(["0", "false", "no", "n", "off"]);

    // 1. Native boolean → return as-is
    if (typeof val === "boolean") {
      return val;
    }

    // 2. Numbers → only 1 or 0
    if (typeof val === "number") {
      if (val === 1) return true;
      if (val === 0) return false;
      return null;
    }

    // 3. Strings → trim, lowercase, then lookup
    if (typeof val === "string") {
      const s = val.trim().toLowerCase();
      if (TRUE_VALUES.has(s)) return true;
      if (FALSE_VALUES.has(s)) return false;
      return null;
    }

    // 4. Everything else → not a recognized boolean
    return null;
  }

  static sanitizeObject(val) {
    // Utility to detect plain objects (not arrays, maps, etc.)
    const isPlainObject = (obj) =>
      Object.prototype.toString.call(obj) === "[object Object]";

    // 1. Must be a non-null plain object
    if (!isPlainObject(val)) {
      return null;
    }

    // 2. Shallow-clone while filtering out dangerous keys
    const result = {};
    for (const [key, v] of Object.entries(val)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        continue;
      }
      result[key] = v;
    }

    // 3. If empty, treat as “no value”
    return Object.keys(result).length > 0 ? result : null;
  }

  static sanitizeEmail(val) {
    // 1. Must be a string
    if (typeof val !== "string") return null;

    // 2. Trim whitespace
    const input = val.trim();
    if (input === "") return null;

    // 3. Locate the “@” and split local & domain
    const atIndex = input.lastIndexOf("@");
    if (atIndex < 1 || atIndex === input.length - 1) return null;
    const local = input.slice(0, atIndex);
    const domain = input.slice(atIndex + 1);

    // 4. Enforce length limits
    if (local.length > 64 || domain.length > 255) return null;
    if (
      domain.split(".").some((label) => label.length < 1 || label.length > 63)
    ) {
      return null;
    }

    // 5. Normalize: lowercase the domain
    const normalized = `${local}@${domain.toLowerCase()}`;

    // 6. Validate against an ASCII-only, RFC-inspired regex
    const emailRegex = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
    if (!emailRegex.test(normalized)) return null;

    return normalized;
  }

  static parseArgs(input, defaults = {}) {
    // 0. Ensure defaults is a plain object
    if (
      defaults == null ||
      typeof defaults !== "object" ||
      Array.isArray(defaults)
    ) {
      throw new TypeError("defaults must be an object");
    }

    // 1. Start with a shallow clone of defaults (immutability)
    const result = { ...defaults };

    // 2. Normalize input into an iterable of [key, value] pairs
    let entries = [];

    if (input == null) {
      // leave entries empty
    } else if (input instanceof URLSearchParams) {
      entries = [...input.entries()];
    } else if (typeof input === "string") {
      entries = [...new URLSearchParams(input).entries()];
    } else if (Array.isArray(input)) {
      // only take pairs of length ≥ 2
      entries = input.filter((pair) => Array.isArray(pair) && pair.length >= 2);
    } else if (
      typeof input === "object" &&
      Object.getPrototypeOf(input) === Object.prototype
    ) {
      entries = Object.entries(input);
    } else {
      // anything else we simply ignore
      entries = [];
    }

    // 3. Merge in, skipping dangerous keys
    for (const [key, value] of entries) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        continue;
      }
      result[key] = value;
    }

    return result;
  }

  static parseUrl(input, component = null) {
    // 1. Must be a string
    if (typeof input !== "string") return false;

    const trimmed = input.trim();
    if (
      trimmed === "" ||
      /[\u0000-\u001F\u007F]/.test(trimmed) || // control chars
      trimmed.length > 2048 // optional: prevent absurdly long
    ) {
      return false;
    }

    // Match full or relative URL
    const urlRegex =
      /^(?:([A-Za-z][A-Za-z\d+\-.]*):)?(?:\/\/([^\/?#:]*)(?::(\d+))?)?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/;
    const match = trimmed.match(urlRegex);
    if (!match) return false;

    const [, rawScheme, rawHost, rawPort, rawPath, rawQuery, rawFragment] =
      match;

    const parts = {
      scheme: rawScheme || null,
      host: rawHost || null,
      port: rawPort ? parseInt(rawPort, 10) : null,
      path: rawPath || null,
      query: rawQuery || null,
      fragment: rawFragment || null,
    };

    // 🛑 Reject if all parts are null or meaningless
    const isMeaningful =
      parts.scheme || parts.host || (parts.path && parts.path.startsWith("/"));
    if (!isMeaningful) return false;

    // Normalize empty strings to null
    for (const key in parts) {
      if (parts[key] === "") parts[key] = null;
    }

    // If specific component requested
    if (component !== null) {
      return Object.prototype.hasOwnProperty.call(parts, component)
        ? parts[component]
        : false;
    }

    return parts;
  }

  static addQueryArg(keyOrParams, valOrUrl, maybeUrl) {
    let params, urlString;

    // CASE 1: keyOrParams is an object of params
    if (
      typeof keyOrParams === "object" &&
      !Array.isArray(keyOrParams) &&
      keyOrParams !== null
    ) {
      params = keyOrParams;
      urlString = String(valOrUrl || "");
    }
    // CASE 2: key is null, undefined, empty → return original URL
    else {
      if (
        keyOrParams === null ||
        keyOrParams === undefined ||
        (typeof keyOrParams !== "string" && typeof keyOrParams !== "number")
      ) {
        return String(maybeUrl || "");
      }
      const keyStr = String(keyOrParams);
      if (keyStr.trim() === "") return String(maybeUrl || "");
      params = { [keyStr]: valOrUrl };
      urlString = String(maybeUrl || "");
    }

    // 2. Split fragment
    const hashIndex = urlString.indexOf("#");
    const fragment = hashIndex >= 0 ? urlString.slice(hashIndex + 1) : "";
    const withoutHash =
      hashIndex >= 0 ? urlString.slice(0, hashIndex) : urlString;

    // 3. Split query
    const qIndex = withoutHash.indexOf("?");
    const base = qIndex >= 0 ? withoutHash.slice(0, qIndex) : withoutHash;
    const queryString = qIndex >= 0 ? withoutHash.slice(qIndex + 1) : "";

    // 4. Modify query params
    const searchParams = new URLSearchParams(queryString);
    try {
      for (const [key, value] of Object.entries(params)) {
        if (value === null || value === undefined || value === false) {
          searchParams.delete(key);
        } else {
          // Safely convert value to string, handle Symbol
          let valString;
          try {
            valString = String(value);
          } catch {
            continue; // skip invalid value
          }
          searchParams.set(key, valString);
        }
      }
    } catch (e) {
      return urlString; // Fallback for totally broken params
    }

    // 5. Reconstruct URL
    let result = base;
    const newQuery = searchParams.toString();
    if (newQuery) result += "?" + newQuery;
    if (fragment) result += "#" + fragment;
    return result;
  }

  /**
   * Determines the element‐type of an array.
   * - If all elements share the same type, returns e.g. "number[]", "string[]", "object[]", "null[]", etc.
   * - Otherwise returns "mixed[]".
   *
   * @param {*} arr
   * @returns {string}  The array’s type annotation.
   * @throws {TypeError} if the input is not an array.
   */
  static getArrayType(arr) {
    if (!Array.isArray(arr)) {
      throw new TypeError("getArrayType expects an array");
    }

    const getType = (item) => {
      if (item === null) return "null";
      if (Array.isArray(item)) return this.getArrayType(item);
      return typeof item;
    };

    const types = arr.map(getType);

    const unique = [...new Set(types)];

    const baseType = unique.length === 1 ? unique[0] : "mixed";

    return `${baseType}[]`;
  }

  static sanitizeHtmlWithWhitelist(input, escapeChars = false) {
    const { JSDOM } = require("jsdom");

    if (typeof input !== "string" || input === "") {
      return "";
    }

    // 1. Parse the input into a DOM with jsdom
    const dom = new JSDOM(`<body>${input}</body>`);
    const document = dom.window.document;

    // 2. Whitelist of tags & their allowed attributes
    const allowedTags = {
      A: ["href", "title", "target", "rel"],
      ABBR: ["title"],
      B: [],
      BLOCKQUOTE: ["cite"],
      BR: [],
      CITE: [],
      CODE: [],
      DEL: ["datetime"],
      EM: [],
      I: [],
      INS: ["datetime"],
      LI: [],
      OL: [],
      P: [],
      Q: ["cite"],
      SPAN: ["style"],
      STRONG: [],
      UL: [],
    };

    // 3. Recursively sanitize the DOM
    function sanitizeNode(node) {
      for (let i = node.childNodes.length - 1; i >= 0; i--) {
        const child = node.childNodes[i];

        if (child.nodeType === dom.window.Node.ELEMENT_NODE) {
          const tag = child.tagName;
          if (!allowedTags[tag]) {
            // Replace disallowed element with its text content
            const text = document.createTextNode(child.textContent);
            node.replaceChild(text, child);
          } else {
            // Strip disallowed attributes
            for (const attr of Array.from(child.attributes)) {
              if (!allowedTags[tag].includes(attr.name.toLowerCase())) {
                child.removeAttribute(attr.name);
              }
            }
            sanitizeNode(child); // Recurse
          }
        } else if (child.nodeType === dom.window.Node.COMMENT_NODE) {
          node.removeChild(child); // Remove comments
        }
      }
    }

    sanitizeNode(document.body);

    // 4. Optionally escape special characters in *text nodes only*
    if (escapeChars) {
      function escapeTextNodes(node) {
        for (let child of Array.from(node.childNodes)) {
          if (child.nodeType === dom.window.Node.TEXT_NODE) {
            child.textContent = child.textContent
              .replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
          } else if (child.nodeType === dom.window.Node.ELEMENT_NODE) {
            escapeTextNodes(child); // Recurse
          }
        }
      }

      escapeTextNodes(document.body);
    }

    // 5. Serialize back to HTML
    return document.body.innerHTML;
  }
}

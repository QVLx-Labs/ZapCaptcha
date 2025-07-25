/*!
 * ZapCaptcha : Human-first cryptographic CAPTCHA system
 * -----------------------------------------------------
 * Designed and developed by QVLx Labs.
 * https://www.qvlx.com
 *
 * © 2024–2025 QVLx Labs. All rights reserved.
 * ZapCaptcha is a proprietary CAPTCHA system for front-end validation without backend server reliance.
 *
 * This software is licensed for non-commercial use and authorized commercial use only.
 * Unauthorized reproduction, redistribution, or tampering is strictly prohibited.
 *
 * ZapCaptcha includes anti-bot measures, DOM mutation traps, and telemetry hooks.
 * Attempted bypass, obfuscation, or automation is a violation of applicable laws and terms of use.
 *
 * To license ZapCaptcha for enterprise/commercial use, contact:
 * security@qvlx.com
 */

// Helper: Convert PEM to CryptoKey
const importPemPublicKey = (() => {
  return async function(pem) {
    try {
      const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----/, "")
                     .replace(/-----END PUBLIC KEY-----/, "")
                     .replace(/\s+/g, "");
      const binaryDer = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      return await crypto.subtle.importKey(
        "spki",
        binaryDer.buffer,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        true,
        ["verify"]
      );
    } catch (err) {
      console.error("ZapCaptcha: importPemPublicKey failed:", err);
      return null;
    }
  };
})();

// Helper: Hash JWK to base64url fingerprint
const hashJwkAsFingerprint = (() => {
  return async function(jwk) {
    const json = JSON.stringify(jwk);
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(json));
    return btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); // base64url
  };
})();

// Base64url decode (used for modulus `n`)
const base64urlToBytes = (() => {
  return function(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4 !== 0) str += '=';
    const binary = atob(str);
    return Uint8Array.from(binary, c => c.charCodeAt(0));
  };
})();

const nonce = () => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

// Helper: Validate PEM key and return { pubKeyObj, fingerprint, valid }
const validateZapPublicKey = (() => {
  return async function(pem) {
    try {
      if (
        !pem ||
        typeof pem !== "string" ||
        !pem.includes("-----BEGIN PUBLIC KEY-----") ||
        !pem.includes("-----END PUBLIC KEY-----")
      ) {
        return { valid: false };
      }

      const pubKeyObj = await importPemPublicKey(pem);
      if (!pubKeyObj) return { valid: false };

      const jwk = await crypto.subtle.exportKey("jwk", pubKeyObj);
      if (jwk.kty !== "RSA" ||
          typeof jwk.n !== "string") {
            return { valid: false };
          }

      const modulusBytes = base64urlToBytes(jwk.n);
      if (modulusBytes.length !== 256) {
        zapMessage("w", "Key rejected. RSA key is not 2048-bit.");
        return { valid: false };
      }

      const fingerprint = await hashJwkAsFingerprint(jwk);
      
      return { 
               valid: true,
               pubKeyObj,
               fingerprint
             };
    } catch (err) {
      console.error("ZapCaptcha: validateZapPublicKey failed:", err);
      return { valid: false };
    }
  };
})();

// Helper: Hash the configs so to catch tampering
const hashZapConfig = (() => {
  return async function(flags, fingerprint = "") {
    const data = { flags, pubKeyFingerprint: fingerprint };
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const digest = await crypto.subtle.digest("SHA-256", encoded);
    return btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); // base64url
  };
})();

let zapReadyResolver;
const zapReadyPromise = new Promise(resolve => {
  zapReadyResolver = resolve;
});

let zapState = (() => {
  let _state = {
    active: false,
    nonce: null,
    configHash: null,
    pubKey: null,
    pubKeyObj: null,
    pubKeyFingerprint: null,
    ephemeral: null
  };

  return Object.freeze({
    init({ nonce, configHash, pubKey, pubKeyObj, pubKeyFingerprint, ephemeral }) {
      _state.active = true;
      _state.nonce = nonce;
      _state.configHash = configHash;
      _state.pubKey = pubKey;
      _state.pubKeyObj = pubKeyObj;
      _state.pubKeyFingerprint = pubKeyFingerprint;
      _state.ephemeral = ephemeral;
    },
    get() {
      return _state;
    },
    isActive() {
      return _state.active;
    }
  });
})();

let zapFlags = (() => {
  let _flags = null;

  return {
    lock: (flags) => {
      if (_flags !== null) return;
      _flags = Object.freeze({ ...flags });
    },
    get: () => _flags,
    getFlag: (key) => _flags?.[key] ?? false,
    isLocked: () => _flags !== null
  };
})();

// Supports numerial (0/1) or string boolean (false/true)
(async function configureZapFlags() {
  const meta = document.querySelector('meta[name="zap-flags"]');
  const metaPubKey = document.querySelector('meta[name="zap-server-pubkey"]');
  const content = meta?.content ?? "";

  const pairs = content.split(",");
  const flags = {};
  let globalSet = null;

  for (const pair of pairs) {
    const [rawKey, rawVal] = pair.split("=").map(s => s.trim());
    if (!rawKey || !rawVal) continue;

    const key = rawKey.toLowerCase();
    const val = (rawVal.toLowerCase() === "true" || rawVal === "1") ? true :
                (rawVal.toLowerCase() === "false" || rawVal === "0") ? false : null;

    if (val === null) continue;
    if (key === "allsec") {
      globalSet = val;
    } else {
      flags[key] = val;
    }
  }

  const finalFlags = {
    checksumJS:              flags["checksumjs"]              ?? globalSet ?? false,
    checksumCSS:             flags["checksumcss"]             ?? globalSet ?? false,
    clickBlockEnforcement:   flags["clickblockenforcement"]   ?? globalSet ?? false,
    functionTamperCheck:     flags["functiontampercheck"]     ?? globalSet ?? false,
    canvasSpoofingCheck:     flags["canvasspoofingcheck"]     ?? globalSet ?? false,
    headlessBrowserCheck:    flags["headlessbrowsercheck"]    ?? globalSet ?? false,
    cssOverrideDetection:    flags["cssoverridedetection"]    ?? globalSet ?? false,
    iframeEmbedCheck:        flags["iframeembedcheck"]        ?? globalSet ?? false,
    iframeInjectCheck:       flags["iframeinjectcheck"]       ?? globalSet ?? false,
    torCheck:                flags["torcheck"]                ?? globalSet ?? false,
    vpnCheck:                flags["vpncheck"]                ?? globalSet ?? false,
    lockShadow:              flags["lockshadow"]              ?? globalSet ?? false,
    monkeyPatching:          flags["monkeypatching"]          ?? globalSet ?? false,
    
    viewportConfined:        flags["viewportconfined"]        ?? true,
    canvasMode:              flags["canvasmode"]              ?? true,
    lockoutsEnabled:         flags["lockoutsenabled"]         ?? true,
    sessionLock:             flags["sessionLock"]             ?? true,
    cookieLock:              flags["cookieLock"]              ?? true,
    extraChallenges:         flags["extrachallenges"]         ?? true,
    
    debugMessages:           flags["debugmessages"]           ?? false,
    consoleWarnings:         flags["consolewarnings"]         ?? false,
    softLock:                flags["softlock"]                ?? false,
    localLock:               flags["localLock"]               ?? false,
    serverMode:              flags["servermode"]              ?? false,
    serverLock:              flags["serverlock"]              ?? false,
    clickDelay:              flags["clickdelay"]              ?? false,
    spawnDelay:              flags["spawndelay"]              ?? false,
    frictionLess:            flags["frictionless"]            ?? false
  };
  if (!finalFlags.serverMode && finalFlags.serverLock) { finalFlags.serverLock = false; }
  zapFlags.lock(finalFlags);
  
  const {
    debugMessages,
    serverMode,
    checksumJS,
    checksumCSS,
    clickBlockEnforcement,
    functionTamperCheck,
    canvasSpoofingCheck,
    headlessBrowserCheck,
    cssOverrideDetection,
    iframeEmbedCheck,
    iframeInjectCheck,
    torCheck,
    vpnCheck,
    lockShadow,
    monkeyPatching,
    viewportConfined,
    canvasMode,
    consoleWarnings,
    lockoutsEnabled,
    sessionLock,
    cookieLock,
    softLock,
    localLock,
    serverLock,
    clickDelay,
    spawnDelay,
    extraChallenges,
    frictionLess
  } = zapFlags.get();

  Object.defineProperty(window, "ZapFlags", {
    get() {
      zapMessage("w", "ZapCaptcha: Access to ZapFlags is restricted.");
      return {
        has: (k) => Object.prototype.hasOwnProperty.call(zapFlags.get(), k)
      };
    },
    configurable: false,
    enumerable: false
  });
  
  if (!zapFlags.getFlag("serverMode")) return;
  
  const rawKey = metaPubKey?.content?.trim() ?? "";
  const { valid, pubKeyObj, fingerprint } = await validateZapPublicKey(rawKey);
  const configHash = await hashZapConfig(finalFlags, valid ? fingerprint : "");
  
  // Generate ephemeral keypair
  const ephemeralKeyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  );

  zapState.init({
    nonce,
    configHash,
    pubKey: valid ? rawKey : null,
    pubKeyObj: valid ? pubKeyObj : null,
    pubKeyFingerprint: valid ? fingerprint : null,
    ephemeral: valid ? Object.freeze(ephemeralKeyPair) : null
  });
  
  if (zapFlags.getFlag("serverMode")) {
    await getZapID(); // Force zapID generation early
  }
  
  if (valid && consoleWarnings) {
    zapMessage("i", "ZapCaptcha: serverMode active, key fingerprint:", fingerprint);
  } else if (!valid) { // Downgrade
    zapMessage("w", "serverMode downgraded due to bad key");
    const patchedFlags = { ...finalFlags, serverMode: false, serverLock: false };
    zapFlags = (() => {
      const _locked = Object.freeze({ ...finalFlags, serverMode: false });
      return {
        lock: () => {}, // prevent further locking
        get: () => _locked,
        getFlag: (k) => _locked[k] ?? false,
        isLocked: () => true
      };
    })();
  }
  zapReadyResolver();
  document.dispatchEvent(new CustomEvent("zapcaptcha-ready")); // TBD
})();

// This function handles console printing to keep things clean
(() => {
  const zapMessageImpl = function zapMessage(level, ...args) {
    if (!zapFlags.getFlag("debugMessages")) return zapMessageImpl;
    const prefix = "ZapCaptcha: ";
    switch (level) {
      case "e":
        console.error(prefix, ...args); break;
      case "i":
        console.info(prefix, ...args); break;
      case "w":
      default:
        console.warn(prefix, ...args); break;
    }
    return zapMessageImpl;
  };

  Object.defineProperty(window, "zapMessage", {
    value: zapMessageImpl,
    writable: false,
    configurable: false,
    enumerable: false
  });
})();

function getCookie(name) {
  const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? match[2] : null;
}

// Clears only local cookies not needed for Zap specifically
const clearAllCookies = (() => {
  return function clearAllCookies() {
    const preserved = ["zapid", "zapLocked"]; // Allowlist
    const cookies = document.cookie.split(";");

    for (let i = 0; i < cookies.length; i++) {
      const cookieName = cookies[i].split("=")[0].trim();

      if (!preserved.includes(cookieName)) {
        document.cookie = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; samesite=strict`;
      }
    }
  };
})();

// SHA-384 Helper
const sha384 = (() => {
  const encoder = new TextEncoder();

  async function compute(str) {
    const buf = encoder.encode(str);
    const digest = await crypto.subtle.digest("SHA-384", buf);
    return Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  Object.freeze(compute); // Lock the inner function
  return compute;
})();

function injectZapChecksumBadge(checksum) {
  document.querySelectorAll(".zcaptcha-box").forEach(box => {
    const wrapper = document.createElement("div");
    wrapper.dataset.zapOkShadow = "1";
    wrapper.style.position = "absolute";
    wrapper.style.bottom = "2px";
    wrapper.style.left = "4px";
    wrapper.style.zIndex = "9999";
    wrapper.style.pointerEvents = "none"; // Prevent blocking other content
    const shadow = wrapper.attachShadow({ mode: "closed" });

    const icon = document.createElement("div");
    icon.textContent = "SHA-384";
    icon.title = `Checksum: sha384-${checksum}`;
    icon.style.cssText = `
      all: initial;
      display: inline-block;
      font-size: 10px;
      font-family: 'Inter', 'Rubik', sans-serif;
      font-family: san-serif;
      padding: 2px;
      border-radius: 4px;
      user-select: none;
      cursor: pointer;
      background: linear-gradient(145deg, #F9DC75, #e6c24e, #fdf0b0);
      color: black;
      box-shadow:
        inset 0 1px 2px rgba(255, 255, 255, 0.3),
        inset 0 -1px 1px rgba(0, 0, 0, 0.2),
        0 0 1px rgba(0, 0, 0, 0.4);
      transition: transform 0.2s ease, opacity 0.2s ease;
      opacity: 0.9;
    `;

    icon.addEventListener("click", () => {
      navigator.clipboard.writeText(checksum);
      icon.textContent = "Copied!";
      setTimeout(() => (icon.textContent = "SHA-384"), 1000);
    });

    shadow.appendChild(icon);
    wrapper.style.position = "absolute";
    wrapper.style.zIndex = "9999";
    box.style.position = "relative"; // Ensure box is positioned
    box.appendChild(wrapper);
  });
}

(async function initZapChecksumBadge() {
  try {
    const checksum = await sha384();
    injectZapChecksumBadge(checksum);
  } catch (err) {
    zapMessage("w", "ZapCaptcha: Failed to compute checksum badge:", err);
  }
})();

const unlockState = (() => {
  return function() {
    if (zapFlags.getFlag("localLock")) {
      try {
        localStorage.removeItem("zapLockedOut");
        if (localStorage.getItem("zapLockedOut") === "1")
          throw new Error("localStorage unlock failed");
      } catch (e) {
        zapMessage("w", "localUnlock failed", e);
      }
    }

    if (zapFlags.getFlag("sessionLock")) {
      try {
        sessionStorage.removeItem("zapLockedOut");
        if (sessionStorage.getItem("zapLockedOut") === "1")
          throw new Error("sessionStorage unlock failed");
      } catch (e) {
        zapMessage("w", "sessionUnlock failed", e);
      }
    }

    if (zapFlags.getFlag("cookieLock")) {
      try {
        document.cookie = "zapLocked=; path=/; max-age=0; expires=Thu, 01 Jan 1970 00:00:00 GMT; samesite=strict";
        const match = document.cookie.match(/(?:^|;\s*)zapLocked=([^;]+)/);
        if (match && match[1] === "1")
          throw new Error("cookie unlock failed");
      } catch (e) {
        zapMessage("w", "cookieUnlock failed", e);
      }
    }

    // Emergency memory and DOM unlock
    try {
      delete window.__zapHardLock;
      document.body.removeAttribute("data-zaplocked");
    } catch (e) {
      zapMessage("w", "memory/DOM unlock failed", e);
    }

    window.dispatchEvent(new Event("zapUnlock")); // User hook
  };
})();

const lockState = (() => {
  return function() {
    if (zapFlags.getFlag("localLock")) {
      try {
        zapMessage("i", "Locked localLock");
        localStorage.setItem("zapLockedOut", "1");
        if (localStorage.getItem("zapLockedOut") !== "1")
          throw new Error("localStorage lock failed");
      } catch (e) {
         zapMessage("w", "ZapCaptcha: localLock failed", e);
      }
    }

    if (zapFlags.getFlag("sessionLock")) {
      try {
       zapMessage("i", "Locked sessionLock");
        sessionStorage.setItem("zapLockedOut", "1");
        if (sessionStorage.getItem("zapLockedOut") !== "1")
          throw new Error("sessionStorage lock failed");
      } catch (e) {
         zapMessage("w", "ZapCaptcha: sessionLock failed", e);
      }
    }

    if (zapFlags.getFlag("cookieLock")) {
      try {
        zapMessage("i", "Locked cookieLock");
        document.cookie = "zapLocked=1; path=/; max-age=31536000; samesite=strict";
        const match = document.cookie.match(/(?:^|;\s*)zapLocked=([^;]+)/);
        if (!match || match[1] !== "1") throw new Error("cookie write failed");
      } catch (e) {
         zapMessage("w", "ZapCaptcha: cookieLock failed", e);
      }
    }

    window.dispatchEvent(new Event("zapLock")); // User hook
  };
})();

// Detect most mobile devices (I think)
const isProbablyMobile = (() => {
  const test = /Mobi|Android|iPhone|iPad|iPod|Windows Phone/i;
  const fn = function() {
    return test.test(navigator.userAgent);
  };
  return fn;
})();

// Helper to build payload destined for server
const buildZapVerificationPayload = (() => {
  return function(extraPayload = {}) {
    const state = zapState.get();
    if (!zapState.isActive()) return null;

    const payload = {
      nonce: state.nonce,
      configHash: state.configHash,
      fingerprint: state.pubKeyFingerprint,
      ...extraPayload
    };

    const serialized = JSON.stringify(payload);
    return { payload, serialized };
  };
})();

// Check server responses to ensure integrity
const verifyZapSignature = (() => {
  return async function(payloadStr, signatureB64) {
    try {
      const pubKey = zapState.get()?.pubKeyObj;
      if (!pubKey) throw new Error("Missing server public key");

      const encoded = new TextEncoder().encode(payloadStr);
      const sigBytes = base64urlToBytes(signatureB64);

      const verified = await crypto.subtle.verify(
        { name: "RSASSA-PKCS1-v1_5" },
        pubKey,
        sigBytes,
        encoded
      );
      return verified;
    } catch (err) {
      /*
        const shortenedPayload = payloadStr.slice(0, 300); // trim to avoid overloading server
        const shortenedSig = signatureB64.slice(0, 100);   // trim for same reason
      
        const desc = [
          "Signature mismatch.",
          "Payload: " + shortenedPayload,
          "Sig (b64): " + shortenedSig
        ].join("\n");
        await zapLockout("Signature verification failed", desc);
       */
       await zapLockout("Signature verification failed");
      return false;
    }
  };
})();

const getZapID = (() => {
  const COOKIE_KEY = "zapid";
  const STORAGE_KEY = "zapid";
  let cachedZapID = null;

  async function generateZapID() {
    const state = zapState.get();
    const fingerprint = state?.pubKeyFingerprint ?? "";
    const data = navigator.userAgent + screen.width + screen.height + fingerprint;
    const encoded = new TextEncoder().encode(data);
    const hashBuf = await crypto.subtle.digest("SHA-256", encoded);
    return btoa(String.fromCharCode(...new Uint8Array(hashBuf)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function getCookieVal() {
    const match = document.cookie.match(/(?:^|;\s*)zapid=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : null;
  }

  function setCookie(zid) {
    document.cookie = `zapid=${encodeURIComponent(zid)}; path=/; max-age=31536000; samesite=strict`;
  }

  function setStorage(zid) {
    localStorage.setItem(STORAGE_KEY, zid);
    sessionStorage.setItem(STORAGE_KEY, zid);
  }

  return async function() {
    if (cachedZapID) return cachedZapID;

    const fromCookie = getCookieVal();
    const fromStorage = localStorage.getItem(STORAGE_KEY);

    // Check for mismatch
    if (fromCookie && fromStorage && fromCookie !== fromStorage) {
      zapMessage("w", "zapID mismatch between cookie and storage");
      return await generateZapID();
    }

    if (fromCookie && fromStorage) {
      cachedZapID = fromCookie;
      return cachedZapID;
    }

    // Generate new zapID
    const zapID = await generateZapID();
    setCookie(zapID);
    setStorage(zapID);
    cachedZapID = zapID;
    return zapID;
  };
})();

const hashUserAgent = (() => {
  return async function() {
    const data = navigator.userAgent + screen.width + screen.height + navigator.language;
    const encoded = new TextEncoder().encode(data);
    const buf = await crypto.subtle.digest("SHA-256", encoded);
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
})();

const zapVerify = (() => {
  return async function(extraPayload = {}) {
    await zapSend("zapVerify", extraPayload);
  };
})();

// Blocks user but not harshly, allowing them to navigate
const zapSoftLock = (() => {
  return function(reason = "softlock triggered") {
    if (!zapFlags.getFlag("lockoutsEnabled")) return;
     zapMessage("i", "ZapCaptcha soft lock: " + reason);

    // Enable all zapcaptcha buttons
    document.querySelectorAll(".zapcaptcha-button").forEach(btn => btn.disabled = true);

    // Add the softlock classes to all boxes
    document.querySelectorAll(".zcaptcha-box").forEach(box => {
      box.classList.add("softlocked");
      box.setAttribute("aria-disabled", "true");

      // Disable all buttons/inputs inside
      box.querySelectorAll("input, button, textarea, select").forEach(el => {
        el.disabled = true;
        el.setAttribute("aria-disabled", "true");
        el.classList.add("softlock-disabled");
      });

      // Prevent any further events
      box.addEventListener("click", e => e.stopImmediatePropagation(), { capture: true });
    });

    document.body.classList.add("zap-softlock-active");
  };
})();

const zapSoftUnlock = (() => {
  return function(reason = "softlock released") {
    if (!zapFlags.getFlag("lockoutsEnabled")) return;
     zapMessage("i", "ZapCaptcha soft unlock: " + reason);

    // Enable all zapcaptcha buttons
    document.querySelectorAll(".zapcaptcha-button").forEach(btn => btn.disabled = false);

    // Remove the softlock classes from all boxes
    document.querySelectorAll(".zcaptcha-box").forEach(box => {
      box.classList.remove("softlocked");
      box.setAttribute("aria-disabled", "false");

      // Enable all buttons/inputs inside the box
      box.querySelectorAll("input, button, textarea, select").forEach(el => {
        el.disabled = false;
        el.setAttribute("aria-disabled", "false");
        el.classList.remove("softlock-disabled");
      });

      // Remove the event listener to allow clicks
      box.removeEventListener("click", e => e.stopImmediatePropagation(), { capture: true });
    });

    // Remove class from body to indicate softlock is no longer active
    document.body.classList.remove("zap-softlock-active");
  };
})();

// Helper: Check for ban conditions
const isBanned = (() => {
  return async function() {
    const useSession = zapFlags.getFlag("sessionLock");
    const useLocal   = zapFlags.getFlag("localLock");
    const useCookie  = zapFlags.getFlag("cookieLock");
    const useServer  = zapFlags.getFlag("serverMode");
    let isLocked = false;

    // If server-only mode is active, bypass all local checks
    if (useServer) {
      try {
        const zapID = await getZapID();
        
        const response = await zapSend("checkLock", {
                  zapID,
                  info: "session-init",
                  ua: navigator.userAgent,
                  lang: navigator.language
                });

        isLocked = response.locked;
        
        if (zapFlags.getFlag("serverLock")) {
          if (isLocked === null) {
             zapMessage("w", "ZapCaptcha: zapSend returned null");
            return null;
          }
  
          if (isLocked) {
            await zapLockout("Server found banned client");
            return true;
          }
          else {
            await zapUnlock("Server found allowed client"); 
            return false;
          }
          return response.locked;
        }
      } catch (err) {
          zapMessage("e", "ZapCaptcha: Server check failed:", err);
          return false; // fail open to avoid deadlocks
      }
    }

    // Otherwise, incorporate or switch to local state
    let banned = false;
    if (useSession) { banned ||= sessionStorage.getItem("zapLockedOut") === "1"; }
    if (useLocal) { banned ||= localStorage.getItem("zapLockedOut") === "1"; }
    if (useCookie) { banned ||= document.cookie.includes("zapLocked=1"); }
    if (useServer) { banned ||=  isLocked; }

    zapMessage("i", "Banned: " + banned);
    return banned;
  };
})();

// Reload page on back/forward navigation to ensure CAPTCHA state resets
window.addEventListener("pageshow", function (e) {
  if (e.persisted) location.reload();
});

// Disable all registered buttons until CAPTCHA loads
document.querySelectorAll(".zapcaptcha-button").forEach(btn => btn.disabled = true);

// Set up a CSSOM sheet
const zapStyleSheet = (() => {
  const style = document.createElement("style");
  const cspNonce = document.querySelector('meta[name="csp-nonce"]')?.content;
  if (cspNonce) {
    style.setAttribute("nonce", cspNonce);
  }
  style.setAttribute("data-zapcaptcha", "true");

  // Safe CSP-compatible fix (Nonce compatible)
  try {
    document.head.appendChild(style);
    if (!style.sheet) {
      zapMessage("w", "CSSOM sheet could not be attached (CSP)");
      return null;
    }
    return style.sheet;
  } catch (e) {
    zapMessage("e", "Failed to create stylesheet under CSP:", e);
    return null;
  }
})();

insertZapRule(".zcap-trap", `
  position: absolute;
  opacity: 0;
  pointer-events: none;
`);

const getCryptoFloat = (() => {
  return function getCryptoFloat(min, max) {
    const buf = new Uint32Array(1);
    crypto.getRandomValues(buf);
    return min + (buf[0] / 0xffffffff) * (max - min);
  };
})();

// Kicks the user via private redirect
const zapHardEject = (() => {
  function doEject() {
    try {
      document.documentElement.innerHTML = "";
      document.body.offsetHeight; // force reflow

      location.replace("https://192.0.2.0");
    } catch {
      try {
        location.replace("about:blank");
      } catch {
        location.href = "about:blank";
      }
    }
  }

  return function ejectNow() {
    try {
      setTimeout(doEject, getCryptoFloat(30, 100));
    } catch (err) {
      zapMessage("e", "Hard eject failed:", err);
    }
  };
})();

const handleServerResponse = (() => {
  return async function handleServerResponse(response) {
    try {
      if (!response || !response.payload || !response.signature) {
        zapMessage("e", "Invalid or missing response payload/signature");
        return;
      }

      const serialized = JSON.stringify(response.payload);
      const isValid = await verifyZapSignature(serialized, response.signature);

      if (!isValid) {
        return;
      }
      
      const isLocked = response.payload.locked;
      
      if (zapFlags.getFlag("serverMode")) {
        const cmd = response.payload.action;
        zapMessage("i", "command =", cmd);
        if (zapFlags.getFlag("lockoutsEnabled") && (cmd === "lockUpdate")) { // Log and process 'locked' state
          if (isLocked === true) {
            await zapLockout("Lock commanded by server", ("Locked: " + response.payload.zapID));
          } else if (isLocked === false) {
            zapMessage("i", "Server unlocked client:", response.payload.zapID);
            await zapUnlock("Unlock commanded by server", ("Unlocked: " + response.payload.zapID));
          }
        }
        else if (cmd === "display") {
          zapMessage("e", "Server cleared display");
        }
        else {
         zapMessage("w", "Unknown server action:", cmd);
        }
      }
    } catch (err) {
      zapMessage("e", "Exception in handleServerResponse:", err);
    }
  };
})();

// Fires messages to the server
const zapSend = (() => {
  async function preparePayload(event, data = {}) {
    const zapID = await getZapID();
    const nonce = `${event}-${Date.now()}`;
    const timestamp = Date.now();
    const state = await zapState.get(); // Wait until zapState init

    const base = {
      event,
      zapID,
      nonce,
      timestamp,
      fingerprint: state?.pubKeyFingerprint || "unknown",
      ...data
    };

    if (event === "zapVerify") { // Only include configHash on zapVerify
      base.configHash = state?.configHash || "missing";
    }

    return base;
  }

  return async function zapSend(event, data = {}) {
    zapMessage("i", "zapSend event:", event);
    zapMessage("i", "zapSend data:", data);
  
    try {
      const waitForKeys = async () => {
        for (let i = 0; i < 50; i++) {
          const s = zapState.get();
          if (s?.ephemeral?.privateKey) return s;
          await new Promise(r => setTimeout(r, 50));
        }
        throw new Error("Ephemeral keypair not initialized (timed out).");
      };
  
      const state = await waitForKeys();
      if (!state) {
        zapMessage("e", "ZapCaptcha: state is undefined.");
        return null;
      }
  
      const payload = await preparePayload(event, data);
      const serialized = JSON.stringify(payload, null, 0);
      const encoder = new TextEncoder();
      const encoded = encoder.encode(serialized);
  
      const signatureBuffer = await crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        state.ephemeral.privateKey,
        encoded
      );
  
      const sigB64 = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
  
      const exportedEphemeral = await crypto.subtle.exportKey("jwk", state.ephemeral.publicKey);
      const ephemeral = {
        kty: "RSA",
        e: exportedEphemeral.e,
        n: exportedEphemeral.n
      };
  
      zapMessage("i", "Payload being sent:", JSON.stringify(payload, null, 2));
  
      const publicKeyMeta = document.querySelector('meta[name="zap-server-pubkey"]');
      if (!publicKeyMeta || !publicKeyMeta.content) {
        zapMessage("w", "Public key meta tag missing or empty");
        return null;
      }
      const publicKey = publicKeyMeta.content;
  
      const response = await fetch("/zapcapture", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          payload,
          signature: sigB64,
          ephemeral,
          publicKey: publicKey
        }),
        keepalive: true
      });
  
      // Ensure the response is valid
      if (!response || !response.ok) {
        zapMessage("w", "Server check failed with status:", response ? response.status : 'No response');
        const responseText = await response.text();  // Read response text only if response is valid
        zapMessage("e", "Error details from server:", responseText);
        return null;
      }

      let serverReply = {};
      try {
        serverReply = await response.json();
        zapMessage("i", "Response from server:", serverReply);
      } catch (e) {
        zapMessage("w", "Failed to parse JSON response:", e);
        const fallbackText = await response.text();
        return null;
      }
      
      await handleServerResponse(serverReply);  // Handle server response
      return serverReply;
    } catch (err) {
      zapMessage("e", "zapSend failed:", err);
    }
  };
})();

// Get wrecked
const zapLockout = (() => {
  return async function(reason = "unspecified", description = "") {
    if (!zapFlags.getFlag("lockoutsEnabled")) return;

    zapMessage("i", "Locking client - " + reason);
    try {
      if (!zapFlags.getFlag("serverLock")) { lockState(); }

      if (zapFlags.getFlag("serverMode") && !zapFlags.getFlag("serverLock")) {
        const zapID = await getZapID();
        await zapSend("zapLockout", {
          zapID,
          reason,
          description,
          page: location.href,
          ua: navigator.userAgent
        });
      }
      if (zapFlags.getFlag("softLock")) { zapSoftLock(); } // Cripple
      else { zapHardEject(); } // Kick
    } catch (e) {
      try {
        location.replace("about:blank");
      } catch {
        location.href = "about:blank";
      }
    }
  };
})();

const zapUnlock = (() => {
  return async function(reason = "unspecified", description = "") {
    if (!zapFlags.getFlag("lockoutsEnabled")) return;
    zapMessage("i", "Unlocking client –", reason);

    if (!zapFlags.getFlag("serverLock")) { unlockState(); }

    try {
      if (zapFlags.getFlag("serverMode") && !zapFlags.getFlag("serverLock")) {
        const zapID = await getZapID();
        await zapSend("zapUnlock", {
          zapID,
          reason,
          description,
          page: location.href,
          ua: navigator.userAgent
        });
      }
      if (zapFlags.getFlag("softLock")) { zapSoftUnlock(); } // Decrippled
    } catch (err) {
      zapMessage("e", "zapUnlock failed:", err);
      location.href = location.origin;
    } 
  };
})();

// Server polling thread
async function pollLock() {
  if (!zapFlags.getFlag("lockoutsEnabled")) { return; }
  
  const isLocked = await isBanned();
  if (isLocked === null) return;
  
  if (isLocked) {
    try {
      if (zapFlags.getFlag("softLock")) { await zapSoftLock(); } // Cripple
      else { await zapHardEject(); } // Kick
    } catch (e) { zapMessage("e", "Fallback lockout failed:", e); }
  }
  else {
    try {
      if (zapFlags.getFlag("softLock")) { await zapSoftUnlock(); } // Decripple
      else {} //zapHardEject(); // TODO
    } catch (e) { zapMessage("e", "Fallback lockout failed:", e); }
  }
}

// Deferred lockout poll after DOMContentLoaded
window.addEventListener("DOMContentLoaded", async () => { pollLock(); });

setInterval(() => { // Repeatedly runs the test function every 10 seconds
  try { pollLock(); }
  catch (e) { zapMessage("e", "Poll error issue: ", e); }
}, 3333);

// Trip mines
async function injectCheckboxTraps() {
  const count = Math.floor(getCryptoFloat(1, 4)); // 1–3 traps

  for (let i = 0; i < count; i++) {
    const trap = document.createElement("input");
    trap.type = "checkbox";
    trap.name = `trap_${crypto.randomUUID()}`;
    trap.classList.add("zcap-trap");

    Object.assign(trap.style, {
      position: "absolute",
      left: `${Math.floor(Math.random() * window.innerWidth)}px`,
      top: `${Math.floor(Math.random() * window.innerHeight)}px`,
      width: "18px",
      height: "18px",
      opacity: "0",
      pointerEvents: "auto",
      zIndex: "9999"
    });

    trap.setAttribute("aria-hidden", "true");
    trap.autocomplete = "off";
    trap.tabIndex = -1;

    trap.addEventListener("change", async () => { await zapLockout("ZapCaptcha honeypot triggered"); });

    document.body.appendChild(trap);
  }

  for (let i = 0; i < 2; i++) {
    const fake = document.createElement("input");
    fake.type = "text";
    fake.name = `fk_${crypto.randomUUID()}`;
    fake.classList.add("zcap-trap");

    Object.assign(fake.style, {
      position: "absolute",
      left: `-9999px`,
      width: "1px",
      height: "1px",
      opacity: "0",
      pointerEvents: "none"
    });

    fake.setAttribute("aria-hidden", "true");
    fake.autocomplete = "off";
    fake.tabIndex = -1;
    document.body.appendChild(fake);
  }

  const radio1 = document.createElement("input");
  radio1.type = "radio";
  radio1.name = "bot_radio";
  radio1.value = "1";
  radio1.classList.add("zcap-trap");

  Object.assign(radio1.style, {
    position: "absolute",
    left: `-9999px`,
    width: "1px",
    height: "1px",
    opacity: "0",
    pointerEvents: "none"
  });

  radio1.setAttribute("aria-hidden", "true");
  radio1.tabIndex = -1;

  const radio2 = radio1.cloneNode();
  radio2.value = "2";

  document.body.appendChild(radio1);
  document.body.appendChild(radio2);
}
injectCheckboxTraps();

// Passive decoys for dumber pests
function injectHoneypotFields() {
  if (!document.body) return;

  const randId = () => crypto.randomUUID().replace(/-/g, "").slice(0, 8);

  const traps = [
    () => {
      const el = document.createElement("input");
      el.name = `email_${randId()}`;
      el.id = `id_email_${randId()}`;
      el.setAttribute("autocomplete", "nope");
      return el;
    },
    () => {
      const el = document.createElement("input");
      el.type = "text";
      el.name = `fax_${randId()}`;
      el.id = `id_fax_${randId()}`;
      el.tabIndex = -1;
      el.setAttribute("autocomplete", "off");
      el.style.display = "none";
      return el;
    },
    () => {
      const el = document.createElement("input");
      el.name = `fax_${randId()}`;
      el.id = `id_fax_${randId()}`;
      el.tabIndex = -1;
      el.setAttribute("autocomplete", "off");
      el.style.position = "absolute";
      el.style.left = "-9999px";
      return el;
    },
    () => {
      const el = document.createElement("input");
      el.type = "checkbox";
      el.name = `terms_${randId()}`;
      el.id = `id_terms_${randId()}`;
      el.required = true;
      el.style.display = "none";
      return el;
    },
    () => {
      const el = document.createElement("input");
      el.name = `honeypot_${randId()}`;
      el.id = `id_honeypot_${randId()}`;
      el.pattern = "^$";
      el.title = "Leave blank";
      el.setAttribute("autocomplete", "off");
      return el;
    },
    () => {
      const el = document.createElement("input");
      el.name = `static_${randId()}`;
      el.id = `id_static_${randId()}`;
      el.readOnly = true;
      el.value = "ZapCaptcha";
      el.style.display = "none";
      return el;
    },
    () => {
      const el = document.createElement("input");
      el.type = "submit";
      el.name = `submit_fake_${randId()}`;
      el.id = `id_submit_fake_${randId()}`;
      el.value = "Submit";
      el.style.display = "none";
      return el;
    },
    () => {
      const el = document.createElement("input");
      el.type = "number";
      el.name = `code_${randId()}`;
      el.id = `id_code_${randId()}`;
      el.step = "999999";
      el.required = true;
      el.style.display = "none";
      return el;
    },
    () => {
      const el = document.createElement("input");
      el.name = `username_${randId()}`;
      el.id = `id_username_${randId()}`;
      el.setAttribute("autocomplete", "off");
      el.setAttribute("spellcheck", "false");
      return el;
    },
    () => {
      const el = document.createElement("select");
      el.name = `os_${randId()}`;
      el.id = `id_os_${randId()}`;
      el.required = true;
      el.style.display = "none";
      const opt1 = new Option("Select...", "");
      const opt2 = new Option("Windows", "windows");
      const opt3 = new Option("Linux", "linux");
      el.append(opt1, opt2, opt3);
      return el;
    },
    () => {
      const el = document.createElement("input");
      el.type = "password";
      el.name = `pass_confirm_${randId()}`;
      el.id = `id_pass_confirm_${randId()}`;
      el.setAttribute("autocomplete", "new-password");
      el.style.display = "none";
      return el;
    },
    () => {
      const el = document.createElement("textarea");
      el.name = `comment_${randId()}`;
      el.id = `id_comment_${randId()}`;
      el.placeholder = "Type your comment here";
      el.maxLength = 300;
      el.style.display = "none";
      return el;
    },
  ];

  // Shuffle and select up to 5
  const shuffled = traps.sort(() => 0.5 - Math.random());
  const count = Math.floor(Math.random() * 5) + 1;

  for (let i = 0; i < count; i++) {
    try {
      const el = shuffled[i]();
      el.classList.add("zcap-trap");
      el.setAttribute("aria-hidden", "true");
      el.tabIndex = -1;
      document.body.appendChild(el);
    } catch (err) {
      zapMessage("w", "Honeypot inject error:", err);
    }
  }
}
injectHoneypotFields()

// Check the traps. Called before verification success.
function checkHoneypotTraps() {
  const traps = document.querySelectorAll(".zcap-trap");
  for (const el of traps) {
    if (!el.name && !el.id) continue;

    const type = el.type || el.tagName.toLowerCase();
    const val = (el.value || "").trim();
    const style = window.getComputedStyle(el);

    // Skip invisible traps
    const hidden = style.display === "none" || style.visibility === "hidden" || style.opacity === "0";
    if (hidden) continue;

    const suspicious =
      (type === "checkbox" || type === "radio") ? el.checked :
      (type === "select-one") ? el.selectedIndex > 0 :
      (type === "submit") ? false :
      (val !== "");

    if (suspicious) {
      zapMessage("w", "Honeypot trap tripped:", el.name || el.id);
      return false;
    }
  }
  return true;
}

// Tor Detection Helper: User-Agent based
function isTorUserAgent() {
  try {
    const ua = navigator.userAgent || "";
    return /TorBrowser|Firefox\/102\.0 ESR/.test(ua);
  } catch {
    return false;
  }
}

// Tor Detection Helper: Navigator fingerprint trap
function isTorNavigatorFingerprint() {
  try {
    return (
      navigator.languages?.length === 0 ||                 // Spoofed to empty
      navigator.webdriver === true ||                      // Set to true in privacy mode
      typeof navigator.hardwareConcurrency === "undefined" ||
      typeof navigator.deviceMemory === "undefined"
    );
  } catch {
    return false;
  }
}

// Tor Detection Helper: Canvas fingerprint block
function isTorCanvasBlocked() {
  try {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    if (!ctx) return true;
    ctx.fillText("test", 10, 10);
    const data = canvas.toDataURL();
    return data.length < 100; // Tor usually blocks or gives tiny output
  } catch {
    return true;
  }
}

// Tor Detection Helper: Audio fingerprinting blocked
function isTorAudioBlocked() {
  try {
    const ctx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 44100, 44100);
    return false;
  } catch {
    return true;
  }
}

// Tor Detection Helper: Plugin trap (usually disabled)
function isTorPluginTrap() {
  try {
    return navigator.plugins.length === 0;
  } catch {
    return true;
  }
}

// Tor Detection Helper: WebGL renderer check
function isTorWebGLBlocked() {
  try {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
    if (!gl) return true;
    const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
    const renderer = debugInfo && gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
    return !renderer || /mesa|software/i.test(renderer); // Common Tor fallback
  } catch {
    return true;
  }
}

// Tor Detection Helper: check for speed anomaly
function isTorConnectionSpeedSuspicious() {
  try {
    const type = navigator.connection?.effectiveType;
    return type === "slow-2g" || type === "2g" || !type;
  } catch {
    return true;
  }
}

// Ban Tor browser if detected. Updated to be shadowed.
// Must use fingerprinting; exit node crosscheck
// not possible for obvious reasons of IP masking 
(async function detectTorBrowser() {
  if (!zapFlags.getFlag("torCheck") && !zapFlags.getFlags("frictionLess")) return;

  const uaHit = isTorUserAgent(); // strong signal
  const hardBlocked = uaHit || isTorWebGLBlocked(); // hard fail cases

  let torScore = 0;
  if (isTorNavigatorFingerprint()) torScore += 1;
  if (isTorCanvasBlocked()) torScore += 1;
  if (isTorAudioBlocked()) torScore += 1;
  if (isTorPluginTrap()) torScore += 1;
  if (isTorConnectionSpeedSuspicious()) torScore += 0.5;

  const isMobile = isProbablyMobile();

  const torDetected = hardBlocked || (!isMobile && torScore >= 2.5);

  if (torDetected) {
    document.cookie = "zaptor=1; path=/; max-age=3600";
    localStorage.setItem("torblock", "1");

    await zapLockout("Tor Browser Detected");

    // Clear the page content
    document.body.innerHTML = "";

    // Create a host for shadow root
    const torRoot = document.createElement("div");
    torRoot.id = "tor-block-root";
    torRoot.dataset.zapOkShadow = "1";
    document.body.appendChild(torRoot);

    // Attach shadow DOM
    const shadow = torRoot.attachShadow({ mode: "closed" });

    // Define HTML template
    const template = document.createElement("template");
    template.innerHTML = `
      <style>
        div#tor-message {
          background: black;
          color: red;
          font-family: sans-serif;
          padding: 2em;
          text-align: center;
        }
      </style>
      <div id="tor-message">
        <h1>❌ Access Blocked</h1>
        <p>Tor Browser is not supported on this site.</p>
      </div>
    `;

    // Inject template into shadow root
    shadow.appendChild(template.content.cloneNode(true));
  }
  return torScore;
})();

// Helper: check for time spoof (To be deprecated)
function isTimezoneMismatch(ipData) {
  try {
    const sysTZ = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    const ipTZ = ipData.timezone || '';
    return ipTZ !== '' && sysTZ !== '' && ipTZ !== sysTZ;
  } catch {
    return false;
  }
}

// VPN Detection Helper: check for known provider in ASN/ORG
function isKnownVPNProvider(ipData) {
  if (!ipData || !ipData.org || !ipData.asn) return false;
  const org = ipData.org.toLowerCase();
  const asn = ipData.asn.toUpperCase();
  zapMessage("i", "vpnCheck org: " + org);
  zapMessage("i", "vpnCheck asn: " + asn);

  const suspiciousASNs = [
    "AS212238", // Datacamp Limited
    "AS9009",   // M247 Ltd
    "AS208722", // Private Layer
    "AS202425", // WorldStream
    "AS49981",  // Worldstream/ProtonVPN
    "AS211252", // VPN Consumer Network
    "AS205621", // Obvious VPN ASN
    "AS397086", // ProtonVPN
    "AS202018", // NordVPN
    "AS393406", // Mullvad
    "AS200753", // ExpressVPN
  ];

 const suspiciousOrgs = [
    "datacamp", "m247", "nordvpn", "proton", "expressvpn", "mullvad",
    "private internet access", "vpn", "hosting", "colo", "cloud", "vps",
    "surfshark", "cyberghost", "server", "worldstream", "leaseweb",
    "netcup", "ovh", "contabo", "digitalocean", "linode", "hetzner",
    "amazon", "aws", "google", "azure", "microsoft", "packet"
  ];
  
 // Also check for bare "asn" fallback
 const asnNum = asn.replace(/^AS/, "");

 return suspiciousASNs.includes(asn) ||
         suspiciousASNs.includes("AS" + asnNum) ||
         suspiciousOrgs.some(keyword => org.includes(keyword));
}

// VPN Detection Helper: check for local spoof
function isLocaleMismatch(ipData) {
  try {
    const region = (navigator.language.split('-')[1] || '').toUpperCase();
    return ipData && ipData.country_code && region !== ipData.country_code.toUpperCase();
  } catch {
    return false;
  }
}

// Helper: check for type faking (To be deprecated)
function isConnectionTypeSuspicious() {
  try {
    const type = navigator.connection?.effectiveType || '';
    return ["unknown", "slow-2g", ""].includes(type);
  } catch {
    return false;
  }
}

// VPN Detection Helper: check RTC
function isWebRTCLeakBlocked() {
  try {
    return typeof RTCPeerConnection === "undefined" || typeof navigator.mediaDevices === "undefined";
  } catch {
    return true;
  }
}

// Detect VPN but only after IP is available
(function detectVPN() {
  if (!zapFlags.getFlag("vpnCheck") && !zapFlags.getFlag("frictionLess")) return;

  document.addEventListener("DOMContentLoaded", async () => {
    let score = 0;
    let ipData = {};

    try {
      const res = await fetch("https://ipapi.co/json/");
      ipData = await res.json();
    } catch (err) {
      zapMessage("w", "VPN Check: Failed to fetch IP info", err);
    }

    // Run checks
    if (isLocaleMismatch(ipData)) {
      zapMessage("i", "VPN Check: Locale mismatch with IP");
      score += 2;
    }

    if (isKnownVPNProvider(ipData)) {
      zapMessage("i", "VPN Check: VPN provider ASN/ORG detected");
      score += 3;
    }

    if (isWebRTCLeakBlocked()) {
      zapMessage("i", "VPN Check: WebRTC leak blocked or unavailable");
      score += 2;
    }

    if (score >= 3) {
      zapLockout("VPN/Anonymizer detected");
    } else {
      zapMessage("i", "ZapCaptcha: No VPN/anonymizer detected (score: " + score + ")");
    }
    return score;
  });
})();

// Freeze critical objects to prevent DOM tampering after rendering
function freezeDOM() {
  try {
    Object.freeze(document.body);
    Object.freeze(document);
  } catch (err) {
    zapMessage("e", "ZapCaptcha freezeDOM failed:", err);
  }
}

// Block user interaction and stop script bubbling
function haltPropagation() {
  try {
    document.body.addEventListener("click", e => e.stopImmediatePropagation(), true);
    document.body.addEventListener("submit", e => e.preventDefault(), true);
    document.body.addEventListener("keydown", e => e.stopImmediatePropagation(), true);
    document.body.addEventListener("mousedown", e => e.stopImmediatePropagation(), true);
  } catch (err) {
    zapMessage("e", "haltPropagation failed:", err);
  }
}

// Optional total DOM wipe, should only be used after rendering fallback
function obliterateDOM() {
  try {
    document.documentElement.innerHTML = "";
  } catch (err) {
    zapMessage("e", "obliterateDOM failed:", err);
  }
}

let zapIframeGuarded = false;
let zapIframeRendered = false;

// Render iframe-blocked message for same-origin fallback
function renderBlockedMessage() {
  if (zapIframeRendered) return; // Singleshot lock
  zapIframeRendered = true;
  try {
    const div = document.createElement("div");
    div.className = "zap-frame-blocked";

    const h1 = document.createElement("h1");
    h1.textContent = "❌ ZapCaptcha Blocked";

    const p = document.createElement("p");
    p.textContent = "This page cannot be embedded in a frame.";

    div.appendChild(h1);
    div.appendChild(p);

    document.body.innerHTML = ""; // clear old content first
    document.body.appendChild(div);
  } catch (e) {
    zapMessage("e", "renderBlockedMessage failed:", e);
  }
}

// Main iframe guard routine with styling and neutralization
function zapIframeGuard() {
  if (!zapFlags.getFlag("iframeEmbedCheck") || zapFlags.getFlag("zapIframeGuarded")) return;
  zapIframeGuarded = true; // Singleshot lock
  if (window.top === window.self) return;

  zapMessage("w", "Iframe embedding detected– attempting neutralization");

  // Inject styles
  try {
    const styleEl = document.createElement("style");
    styleEl.setAttribute("data-zapcaptcha", "iframe-block");
    const nonce = document.querySelector('meta[name="csp-nonce"]')?.content;
    if (nonce) styleEl.setAttribute("nonce", nonce);
    document.head.appendChild(styleEl);

    const zapStyleSheet = styleEl.sheet;
    if (zapStyleSheet) {
      zapStyleSheet.insertRule(`
        .zap-frame-blocked {
          height: 100% !important;
          width: 100% !important;
          background: black !important;
          color: red !important;
          font-family: sans-serif !important;
          padding: 2em !important;
          text-align: center !important;
        }
      `);
    }
  } catch (e) {
    zapMessage("e", "Failed to insert iframe-block CSS rule", e);
  }

  // Render message and lock DOM on next animation frame
  requestAnimationFrame(() => {
    renderBlockedMessage();
    haltPropagation();
    freezeDOM();
  });

  // Fallback in case RAF fails or DOM wasn't ready
  setTimeout(() => {
    if ((window.top !== window.self) && !zapIframeRendered) {
      renderBlockedMessage();
      haltPropagation();
      freezeDOM();
    }
  }, 300);

  // Try to break out of iframe (cross-origin may fail silently)
  try {
    window.top.location = window.location.href;
    top.location = self.location;
    window.top.location.replace(window.location.href);
  } catch (e) {
    zapMessage("w", "Top redirect failed – likely cross-origin");
  }
}
zapIframeGuard();

// ZapCaptcha Anti-Iframe Disarming Logic
window.addEventListener("DOMContentLoaded", () => {
  if (!zapFlags.getFlag("iframeInjectCheck")) { return; }
  function disarmIframes() {
    const disarm = iframe => {
      if (!(iframe instanceof HTMLIFrameElement)) return;
      zapMessage("w", "Disarming iframe:", iframe);
      try {
        iframe.src = "https://192.0.2.0";
        setTimeout(() => {
          try {
            iframe.remove();
          } catch { // fallback
            try {
              iframe.parentNode?.removeChild(iframe);
            } catch {} // NOP for now
          }
        }, 30);
      } catch {
        try {
          iframe.parentNode?.removeChild(iframe);
        } catch {} // NOP for now
      }
    };

    document.querySelectorAll("iframe").forEach(disarm);

    const observer = new MutationObserver(mutations => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node instanceof HTMLIFrameElement) {
            disarm(node);
          } else if (node.nodeType === 1 && typeof node.querySelectorAll === "function") {
            node.querySelectorAll("iframe").forEach(disarm);
          }
        }
      }
    });

    observer.observe(document.body, { childList: true, subtree: true });
  }

  disarmIframes();
  setInterval(disarmIframes, 2000);
});

// Compute SHA-384 hash of canvas pixels
function getCanvasPixelFingerprint(canvas) {
  const ctx = canvas.getContext("2d");
  if (!ctx) return Promise.resolve("nullctx");

  const pixels = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
  return crypto.subtle.digest("SHA-384", pixels.buffer).then(hashBuffer => {
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  });
}

// Store fingerprint after CAPTCHA renders
let zapCanvasFingerprint = null; // Renamed for clarity
function storeZapCaptchaFingerprint(canvas) {
  return getCanvasPixelFingerprint(canvas).then(fp => {
    zapCanvasFingerprint = fp;
    zapMessage("i", "Canvas fingerprint stored -> ", fp);
  });
}

// Validate at time of check
function validateZapCaptchaFingerprint(canvas) {
  return getCanvasPixelFingerprint(canvas).then(currentFp => {
    const isMatch = zapCanvasFingerprint === currentFp;
    if (!isMatch) {
     zapMessage("w", "Canvas fingerprint mismatch!");
    } else {
      zapMessage("i", "Canvas fingerprint verified.");
    }
    return isMatch;
  });
}

// Helper to handle dynamic transforms
function setTransform(el, transformString) {
  el.style.setProperty("--zcap-transform", transformString);
  el.classList.add("zap-transform");
}

// Helper to insert rules without duplicates
function insertZapRule(selectorOrRule, rules = null) {
  if (!zapStyleSheet) return;

  let ruleText;

  if (rules === null) {
    // Full rule was passed directly (e.g. @media block)
    ruleText = selectorOrRule.trim();
  } else {
    // Normal selector + rules
    ruleText = `${selectorOrRule} { ${rules} }`;
  }

  // Prevent duplicate rules
  const exists = Array.from(zapStyleSheet.cssRules).some(r => r.cssText === ruleText);
  if (!exists) {
    try {
      zapStyleSheet.insertRule(ruleText, zapStyleSheet.cssRules.length);
    } catch (e) {
      zapMessage("e", "Failed to insert rule:", ruleText, e);
    }
  }
}

// This helps out a bit with FOUC and double prevents no-js bypass
(function injectCriticalCSS() {
  insertZapRule(".zcaptcha-label:not(.verified) .label-verified", `
    display: none !important;
    opacity: 0 !important;
    transform: scale(0.95) !important;
  `);

  insertZapRule(".zcaptcha-label.verified .label-unverified", `
    display: none !important;
    opacity: 0 !important;
    transform: scale(0.95) !important;
  `);
  insertZapRule(`@media (scripting: none) {
    * {
      display: none !important;
    }
  }`);
})();

// Lock up all clicks except for links
const preventTextCopyAndRightClick = (function () {
  function blockCopyAndContext() {
    if (!zapFlags.getFlag("clickBlockEnforcement")) { return; }

    insertZapRule("body.nocopy, body.nocopy *", `
      user-select: none !important;
      -webkit-user-select: none !important;
      -moz-user-select: none !important;
      -ms-user-select: none !important;
    `);

    document.body.classList.add("nocopy");

    document.addEventListener("contextmenu", function (e) {
      e.preventDefault();
      e.stopPropagation();
    }, true);

    document.addEventListener("copy", function (e) {
      e.preventDefault();
      alert("Zapcaptha security: Copying is disabled on this page.");
    });
  }

  // Immediately invoke once
  blockCopyAndContext();

  // Return for later manual use
  return blockCopyAndContext;
})();

Object.defineProperty(window, "preventTextCopyAndRightClick", {
  value: preventTextCopyAndRightClick,
  writable: false,
  configurable: false
});

// Detect setTimeout, console.log, addEventListener monkey-patching
(async function detectFunctionTampering() {
  if (!zapFlags.getFlag("functionTamperCheck")) { return; }
  const originals = {
    setTimeout: window.setTimeout,
    setInterval: window.setInterval,
    consoleLog: console.log,
    consoleError: console.error,
    addEventListener: window.addEventListener
  };

  setTimeout(async () => {
    try {
      if (
        window.setTimeout !== originals.setTimeout ||
        window.setInterval !== originals.setInterval ||
        console.log !== originals.consoleLog ||
        console.error !== originals.consoleError ||
        window.addEventListener !== originals.addEventListener
      ) {
        await zapLockout("Function override detected");
      }
    } catch (e) {
      zapMessage("w", "Function override error: " + e);
    }
  }, 1000);
})();

// Detect headless browser
(async function detectHeadlessBrowser() {
  if (!zapFlags.getFlag("headlessBrowserCheck")) return;

  const ua = navigator.userAgent || "";

  const isMobile = /Mobi|Android|iPhone|iPad/i.test(ua);
  const isHeadlessUA = /HeadlessChrome|puppeteer|phantomjs|selenium/i.test(ua);
  const isWebDriver = navigator.webdriver === true;

  // Only block if all signals point to headless AND we're not on mobile
  const block = !isMobile && (isWebDriver || isHeadlessUA);

  if (block) { await zapLockout("Headless browser detected"); }

  // Stealth fingerprint mismatch
  navigator.permissions?.query({ name: 'notifications' }).then(p => {
    if (!isMobile && Notification.permission === 'denied' && p.state === 'prompt') {
      zapMessage("w", "Possible stealth headless environment");
    }
  });
  return block;
})();

// Detect element CSS tampering
(async function detectCSSOverride() {
  if (!zapFlags.getFlag("cssOverrideDetection")) { return; }
  const el = document.querySelector('.zcaptcha-box');
  if (!el) return;
  const style = window.getComputedStyle(el);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
    await zapLockout("Style override");
  }
})();

// Periodic zapcaptcha.js Integrity Check
(async function checkZapCaptchaJS() {
  if (!zapFlags.getFlag("checksumJS")) { return; }
  const meta = document.querySelector('meta[name="zap-js-integrity"]');
  if (!meta || !meta.content || !meta.content.startsWith("sha384-")) return;

  const expected = meta.content.trim();

  async function performCheck() {
    fetch("zapcaptcha.js")
      .then(r => r.ok ? r.text() : Promise.reject("Failed to fetch zapcaptcha.js"))
      .then(text => sha384(text))
      .then(async hash => {
        const actual = "sha384-" + hash;
        if (actual !== expected) {
          // ZapLockout("zapcaptcha.js hash mismatch",`Expected: ${expected}\nActual: ${actual}`);
          await ZapLockout("zapcaptcha.js hash mismatch");
        }
      })
      .catch(err => {
       zapMessage("e", "JS Integrity Check Failed- ", err);
      });
    }
    
  performCheck(); // Initial check
  setInterval(performCheck, 10000); // Poll every x seconds
})();

// Detect absence of any human interaction
function checkHumanInteraction() {
  let interacted = false;
  const markInteracted = () => { interacted = true; };

  window.addEventListener("mousemove", markInteracted, { once: true });
  window.addEventListener("touchstart", markInteracted, { once: true });
  window.addEventListener("keydown", markInteracted, { once: true });

  if (!interacted) {
    console.warn("No human interaction detected. Possible headless bot.");
    return true;
  }
}

// Periodic zapcaptcha.css Integrity Check
(async function checkZapCaptchaCSS() {
  if (!zapFlags.getFlag("checksumCSS")) return;

  const meta = document.querySelector('meta[name="zap-css-integrity"]');
  if (!meta || !meta.content || !meta.content.startsWith("sha384-")) return;

  const expected = meta.content.trim();
  const cssHref = "zapcaptcha.css";

  async function performCheck() {
    // Only run after zapcaptcha.css is available in DOM
    const link = document.querySelector(`link[href*="${cssHref}"]`);
    if (!link) return; // Skip until stylesheet is injected

    fetch(cssHref)
      .then(r => r.ok ? r.text() : Promise.reject("Failed to fetch zapcaptcha.css"))
      .then(text => sha384(text))
      .then(async hash => {
        const actual = "sha384-" + hash;
        if (actual !== expected) {
          // await zapLockout("zapcaptcha.css hash mismatch", `Expected: ${expected}\nActual: ${actual}`);
          await zapLockout("zapcaptcha.css hash mismatch");
        }
      })
      .catch(err => {
          zapMessage("e", "CSS Integrity Check Failed");
      });
  }

  // Retry every 5s until stylesheet is live, then poll
  let cssCheckStarted = false;
  const tryStartCheck = setInterval(() => {
    if (document.querySelector(`link[href*="${cssHref}"]`)) {
      if (!cssCheckStarted) {
        cssCheckStarted = true;
        clearInterval(tryStartCheck);
        performCheck();
        setInterval(performCheck, 10000); // re-check every 10s
      }
    }
  }, 1000);
})();

// Ensure styling of captcha is constant
(function injectZapCaptchaCSS() {
  const existing = document.querySelector('link[href*="zapcaptcha.css"]');
  if (!existing) {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "https://zapcaptcha.com/zapcaptcha.css";
    document.head.appendChild(link);
  }
})();

function getDelays() {
  return {
    click: zapFlags.getFlag("clickDelay") ? getCryptoFloat(10, 1000) : 0,
    spawn: zapFlags.getFlag("spawnDelay") ? getCryptoFloat(10, 1000) : 0,
    submit: zapFlags.getFlag("serverMode") ? 1000 : getCryptoFloat(800, 1400)
  };
}

//////////////////////////////////////////////////////////////////////////////////////
// Main IIFE
//////////////////////////////////////////////////////////////////////////////////////
(async function () {
  const verifiedMap = new Map();
  const timeoutMap = new Map();
  const signalMap = new WeakMap();
  const canvasMap = new WeakMap(); // For canvas bouncer object
  const bouncerMap = new WeakMap(); // For DOM bouncer object
  const extraMap = new WeakMap(); // For shadow challenge
  
  const NONCE_COOKIE_PREFIX = "zc_";

  function getStorageName(box) {
    if (!box) return "default";
    if (box.dataset.zcapId) return box.dataset.zcapId;
  
    // Fall back to data-target-id if explicitly set
    const targetId = box.getAttribute("data-target-id");
    if (targetId) return `zcid_${targetId}`;
  
    // Absolute fallback: give hardcoded label (won't break anything)
    return "zcid_fallback";
  }

  function allowEventDispatch(box) {
    signalMap.set(box, true);
  }
  
  function dispatchIfLegit(box, evt) {
    if (signalMap.get(box)) box.dispatchEvent(evt);
  }

  function generateNonce() {
    const nonce = crypto.randomUUID();
    const secret = getStorageName(document.querySelector(`[data-zcap-id]`));
    const signature = hmac(nonce, secret);
    return `${nonce}:${signature}`;
  }
  
  async function hmac(message, key) {
    const enc = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey(
      "raw", enc.encode(key), { name: "HMAC", hash: "SHA-384" }, false, ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(message));
    return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  async function verifyNonceAsync(box) {
    const name = getStorageName(box);
    const stored = sessionStorage.getItem(`${NONCE_COOKIE_PREFIX}${name}`) || "";
    const [raw, sig] = stored.split(":");
    if (!raw || !sig) return false;
    const expectedSig = await hmac(raw, name);
    return sig === expectedSig;
  }
  
  async function setNonceAsync(box) {
    const name = getStorageName(box);
    const nonce = await generateNonce(box);
    try {
      document.cookie = `${NONCE_COOKIE_PREFIX}${name}=${nonce}; path=/; SameSite=Strict`;
    } catch {}
    try {
      sessionStorage.setItem(`${NONCE_COOKIE_PREFIX}${name}`, nonce);
    } catch {}
  }

  function getNonce(box) {
    const name = getStorageName(box);
    let value = null;
    try {
      const cookie = document.cookie.split("; ").find(c => c.startsWith(`${NONCE_COOKIE_PREFIX}${name}=`));
      value = cookie?.split("=")[1] || null;
    } catch {}
    if (!value) {
      try {
        value = sessionStorage.getItem(`${NONCE_COOKIE_PREFIX}${name}`) || null;
      } catch {}
    }
    return value;
  }

  function clearNonce(box) {
    const name = getStorageName(box);
    try {
      document.cookie = `${NONCE_COOKIE_PREFIX}${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
    } catch {}
    try {
      sessionStorage.removeItem(`${NONCE_COOKIE_PREFIX}${name}`);
    } catch {}
  }
  
  insertZapRule(".zcap-timeout-message", `
    color: red;
    font-size: 0.9em;
    margin: 0;
  `);

  function showTimeoutMessage(box, timeoutSec) {
    if (!box) return;
    
    if (zapFlags.getFlag("lockoutsEnabled") && box.classList.contains("softlocked")) { return; }
  
    // Create new message
    const msg = document.createElement("div");
    msg.setAttribute("aria-live", "assertive");
    msg.setAttribute("role", "alert");
    msg.className = "zcap-timeout-message";
    msg.textContent = "Captcha expired. Please retry.";
  
    // Style it visibly (override if needed)
    msg.classList.add("zcap-timeout-message");

  
    box.appendChild(msg);
  
    // Dispatch event (optional for advanced users)
    /* 
    box.dispatchEvent(new CustomEvent("zapcaptcha-expired", {
      detail: { timestamp: Date.now() }
    }));
    */
    dispatchIfLegit(box, new CustomEvent("zapcaptcha-expired", {
      detail: { timeout: timeoutSec, timestamp: Date.now() }
    }));
  }

  // Wipe the timeout visual clean
  function removeTimeoutMessage(box) {
    if (!box) return;
    const msg = box.querySelector(".zcap-timeout-message");
    if (msg) msg.remove();
  }
  
  // Clear any previous timeout for this trigger
  function clearTimeoutWatcher(elOrId) {
    const id = typeof elOrId === "string" ? elOrId : elOrId?.id;
    const existing = timeoutMap.get(elOrId) || timeoutMap.get(id);
    if (existing) clearTimeout(existing);
    timeoutMap.delete(elOrId);
    timeoutMap.delete(id);
  }

  // This function only handles how timeout even happens and
  // the resultant expiration. TODO: make expiration configurable
  // 
  // FYI:
  // Timeout is set by data field in meta tag or default 1 min.
  // Timeout can happen in two cases:
  //   1. Challenge not completed in the set time
  //   2. Challenge completed but sits for a time
  function setTimeoutWatcher(box, triggerEl) {    
    const timeoutAttr = box?.getAttribute("data-zcap-timeout");
    const timeoutSec = parseInt(timeoutAttr, 10);
    if (!timeoutSec || isNaN(timeoutSec) || timeoutSec < 3) return;

    clearTimeoutWatcher(triggerEl);
  
    // Only skip if this is a frictionless box and extraMap marks it
    if (
      box?.dataset.zcapFrictionless === "1" &&
      typeof extraMap !== "undefined" &&
      extraMap.get(triggerEl)
    ) {
      return;
    }
  
    const timeoutId = setTimeout(() => {
      const trueBox = document.querySelector(`.zcaptcha-box[data-target-id="${triggerEl.id}"]`) || box;
      
      verifiedMap.delete(triggerEl);
      triggerEl.removeAttribute("data-zcap-verified-at");
      clearNonce(trueBox);
  
      let label = box.querySelector(".zcaptcha-label") || box.querySelector(".zcaptcha-left span");
      label?.classList.remove("verified");
  
      showTimeoutMessage(trueBox, timeoutSec);
      
      // Auto-remove the expiration message after a delay (optional)
      setTimeout(() => {
        const expiredMsg = trueBox.querySelector(".zcap-timeout-message");
        if (expiredMsg) expiredMsg.remove();
      }, 6000); // Remove after 6s, tweak as needed
      
      // Destroy DOM mode bouncer if exists
      const bouncer = bouncerMap.get(triggerEl);
      if (bouncer) {
        if (bouncer._raf) cancelAnimationFrame(bouncer._raf);
        fadeAndRemove(bouncer);
        bouncerMap.delete(triggerEl); // cleanup
      }
      
      // Destroy canvas if exists
      const canvas = canvasMap.get(triggerEl);
      if (canvas) {
        if (canvas._raf) cancelAnimationFrame(canvas._raf);
        canvas.remove();
        canvasMap.delete(triggerEl); // cleanup
      }
        
      // Remove overlay if no other CAPTCHA is currently verified and within timeout
      let shouldRemoveOverlay = true;
      for (const [otherTrigger, ts] of verifiedMap.entries()) {
        if (otherTrigger === triggerEl) continue;
      
        const otherBox = document.querySelector(`.zcaptcha-box[data-target-id="${otherTrigger.id}"]`);
        const otherTimeoutAttr = otherBox?.getAttribute("data-zcap-timeout");
        const otherTimeoutSec = parseInt(otherTimeoutAttr, 10) || 60;
        const otherTimestamp = parseInt(otherTrigger.dataset.zcapVerifiedAt || "0", 10);
        const age = (Date.now() - otherTimestamp) / 1000;
      
        if (age < otherTimeoutSec) { shouldRemoveOverlay = false; break; }
      }
      
      if (shouldRemoveOverlay) {
        UIOverlayManager.enable(triggerEl);
      }

      trueBox.dispatchEvent(new CustomEvent("zapcaptcha-expired", {
        detail: {
          timeout: timeoutSec,
          timestamp: Date.now()
        }
      }));
  
      timeoutMap.delete(triggerEl); // Clean up
    }, timeoutSec * 1000);
  
    timeoutMap.set(triggerEl, timeoutId);
  }
  
  // Capture submits
  document.addEventListener("submit", function(e) {
    const form = e.target;
    const box = form.closest(".zcaptcha-box[data-zcap-frictionless='1']");
    if (!box) return;
  
    const triggerId = box.dataset.targetId;
    const trigger = document.getElementById(triggerId);
  
    const isVerified = trigger && verifiedMap.get(trigger);
    if (!isVerified) {
      e.preventDefault();
      e.stopImmediatePropagation();
      zapMessage("i", "Form blocked: frictionless CAPTCHA not yet passed.");
    }
  }, true);
  
  // Block keys before checks so nothing gets through
  (function trapKeysDuringFrictionless() {
    function trap(e) {
      if (document.querySelector('.zcaptcha-box[data-zcap-frictionless="1"]')) {
        const isVerified = [...document.querySelectorAll('.zcaptcha-box[data-zcap-frictionless="1"]')].every(box => {
          const trigger = document.getElementById(box.dataset.targetId);
          return verifiedMap.get(trigger);
        });
  
        if (!isVerified) {
          e.preventDefault();
          e.stopImmediatePropagation();
          return false;
        }
      }
    }
  
    window.addEventListener("keydown", trap, true);
    window.addEventListener("keypress", trap, true);
    window.addEventListener("keyup", trap, true);
  })();

  async function launchFrictionlessMode() {
    const boxes = Array.from(document.querySelectorAll('.zcaptcha-box[data-zcap-frictionless="1"]'));
    if (!boxes.length) return;
    
    for (const box of boxes) {
      const trigger = document.querySelector(`[id="${box.dataset.targetId}"]`);
    
      // Blur active
      if (document.activeElement && box.contains(document.activeElement)) { document.activeElement.blur(); }
    
      // Also disable all inputs inside the box
      const inputs = box.querySelectorAll("input, textarea, button, select");
      inputs.forEach(input => input.setAttribute("disabled", "true"));
    }
    
    // Disable all trigger buttons while scanning
    boxes.forEach(box => {
      const trigger = document.querySelector(`[id="${box.dataset.targetId}"]`);
      if (trigger) UIOverlayManager.softDisable(trigger);
    });
  
    const overlays = [];
  
    await new Promise(r => requestAnimationFrame(() => { requestAnimationFrame(r); })); // Need to wait
  
    // Create overlays
    for (const box of boxes) {
      const boxRect = box.getBoundingClientRect();
      const host = document.createElement("div");
  
      host.style.position = "absolute";
      host.style.top = `${boxRect.top + window.scrollY}px`;
      host.style.left = `${boxRect.left + window.scrollX}px`;
      host.style.width = `${boxRect.width}px`;
      host.style.height = `${boxRect.height}px`;
      host.style.zIndex = "9999";
      host.style.pointerEvents = "none";
      host.style.borderRadius = getComputedStyle(box).borderRadius || "8px";
      host.dataset.zapOkShadow = "1";
  
      document.body.appendChild(host);
      const shadow = host.attachShadow({ mode: "open" });
      shadow.innerHTML = `
        <style>
          .frictionless-mask {
            width: 100%;
            height: 100%;
            background: yellow;
            font-weight: bold;
            font-style: italic;
            opacity: 0.8;
            border: 2px solid black;
            border-radius: inherit;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: inherit;
            font-size: 26px;
            color: black;
          }
        </style>
        <div class="frictionless-mask" id="flmask">Analyzing</div>
      `;
      const span = shadow.getElementById("flmask");
      let dotState = 0;
      const interval = setInterval(() => {
        dotState = (dotState + 1) % 10;
        span.textContent = "Analyzing" + ".".repeat(dotState);
      }, 500);
      overlays.push({ host, interval });
    }
    
    async function realignOverlays() {
      for (let i = 0; i < boxes.length; i++) {
        const box = boxes[i];
        const host = overlays[i].host;
        const boxRect = box.getBoundingClientRect();

        host.style.top = `${boxRect.top + window.scrollY}px`;
        host.style.left = `${boxRect.left + window.scrollX}px`;
        host.style.width = `${boxRect.width}px`;
        host.style.height = `${boxRect.height}px`;
      }
    }
    
    await new Promise(r => requestAnimationFrame(r));
    realignOverlays();
    
    // Adjust when screen rescale, move, or viewport changes
    window.addEventListener("resize", realignOverlays);
    window.addEventListener("scroll", realignOverlays, true);
    
    // Optionally: set interval fallback if OS doesn't dispatch resize
    const fallbackTimer = setInterval(realignOverlays, 500);
  
    // Run checks
    const DURATION = 25000;
    const startTime = Date.now();
    const scores = [];
  
    const collectScore = async (fn) => {
      try {
        const result = await fn();
        if (typeof result === "number") scores.push(result);
      } catch (e) {
        zapMessage("w", "Frictionless check failed", e);
      }
    };
  
    const checks = [
      () => detectTorBrowser(),
      () => detectVPNS(),
      () => detectHeadlessBrowser().then(b => b ? 1 : 0),
      () => checkHumanInteraction()
    ];
  
    await Promise.allSettled(checks.map(collectScore));
  
    const avgScore = scores.reduce((a, b) => a + b, 0) / (scores.length || 1);
    const passed = avgScore >= 1.5 && scores.length >= 3;
    const delayRemaining = Math.max(0, DURATION - (Date.now() - startTime));
  
    setTimeout(async () => {
      try {
        overlays.forEach(({ host, interval }) => {
          clearInterval(interval);
          host.remove();
        });
  
        // Uncomment to enforce passing
        // if (!passed) {
        //   await zapLockout("Frictionless CAPTCHA failed");
        //   return;
        // }
  
        for (const box of boxes) {
          const triggerEl = document.querySelector(`[id="${box.dataset.targetId}"]`);
          if (!triggerEl) continue;
  
          verifiedMap.set(triggerEl, true);
          triggerEl.dataset.zcapVerifiedAt = Date.now();
          await setNonceAsync(box);
  
          const label = box.querySelector(".zcaptcha-label");
          if (label) {
            label.classList.add("verified");
            label.setAttribute("aria-checked", "true");
          }
  
          dispatchIfLegit(box, new CustomEvent("zapcaptcha-verified", {
            detail: { timestamp: Date.now(), id: getStorageName(box) }
          }));
  
          UIOverlayManager.softEnable(triggerEl);
          clearInterval(fallbackTimer);
          window.removeEventListener("resize", realignOverlays);
          window.removeEventListener("scroll", realignOverlays, true);
        }
  
      } catch (err) {
        zapMessage("e", "Frictionless finalization error", err);
      }
    }, delayRemaining);
  }
  
  if (zapFlags.getFlag("frictionLess")) {
    window.addEventListener("DOMContentLoaded", () => {
      setTimeout(() => {
        launchFrictionlessMode();
      }, 1000); // slight delay if needed
    });
  }

  window.ZapCaptcha = {
    async verify(triggerEl, onSuccess) {
      const DELAYS = getDelays();
      const triggerId = triggerEl.getAttribute("id");
      const box = document.querySelector(`.zcaptcha-box[data-target-id="${triggerEl.id}"]`);

      // Frictionless CAPTCHAs here
      if (box?.dataset.zcapFrictionless === "1" && zapFlags.getFlag("frictionLess")) {
        if (verifiedMap.get(triggerEl)) {
          zapMessage("i", "ZapCaptcha frictionless verified (pre-pass)");
          onSuccess?.();
          return;
        } else {
          zapMessage("w", "ZapCaptcha not yet frictionless-verified");
          return; // Don't launch challenge
        }
      }
      
      // Watchdog definition
      const tamperWatcher = new MutationObserver((mutations) => {
        for (const m of mutations) {
          if (m.type === "childList") {
            if (!document.body.contains(box)) {
              zapMessage("w", "Box detached — restoring");
              document.body.appendChild(box);
            }
          }
          if (m.type === "attributes" && m.attributeName === "class") {
            const isNowVerified = box.classList.contains("verified") || box.querySelector(".zcaptcha-label")?.classList.contains("verified");
            if (isNowVerified && !verifiedMap.get(triggerEl)) {
              (async () => { await zapLockout("ZapCaptcha tamper: class spoofing detected"); })();
            }
          }
        }
      });
      tamperWatcher.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["class"]
      });
      
      if (!box) { zapMessage("e","Failed to find box for trigger: ", triggerEl.id); return; }
      
      if (zapFlags.getFlag("lockoutsEnabled") && box.classList.contains("softlocked")) {
        zapMessage("w", "Verification blocked due to softlock"); return;
      }
      const timestamp = triggerEl.dataset.zcapVerifiedAt;
      const lastNonce = getNonce(box);
      const now = Date.now();
      const useCanvasMode = zapFlags.getFlag("canvasMode");

      clearTimeoutWatcher(triggerEl);
      removeTimeoutMessage(box);

     if (verifiedMap.get(triggerEl) && timestamp && lastNonce) {
        const timeoutAttr = box?.getAttribute("data-zcap-timeout");
        const timeoutSec = parseInt(timeoutAttr, 10) || 120;
        const age = (now - parseInt(timestamp)) / 1000;
        if (age < timeoutSec && lastNonce === sessionStorage.getItem(`${NONCE_COOKIE_PREFIX}${getStorageName(box)}`)) {
          const canvas = box.querySelector("canvas");
        
          if (useCanvasMode && canvas) {
            return validateZapCaptchaFingerprint(canvas).then(isValid => {
              if (zapFlags.getFlag("canvasSpoofingCheck") && !isValid) {
                (async () => { await zapLockout("Canvas fingerprint validation failed"); })();
              } else { return onSuccess?.(); }
            });
          } else { return onSuccess?.(); } // DOM fallback
        }
      }

      const form = triggerEl.closest("form");
      if (form && !form.checkValidity()) { form.reportValidity(); return; }

      UIOverlayManager.disable(triggerEl);
      setTimeout(() => {
        setTimeoutWatcher(box, triggerEl);

        allowEventDispatch(box);
        const launchFunc = useCanvasMode ? launchZcaptchaCanvas : launchZcaptchaDOM;
        const lbl = box.querySelector(".zcaptcha-label");
        lbl?.classList.remove("verified");
        
        allowEventDispatch(box); // Spoof defense
        
        launchFunc(triggerEl, DELAYS, async () => {
          verifiedMap.set(triggerEl, true);
          triggerEl.dataset.zcapVerifiedAt = Date.now();
          const newNonce = generateNonce();
          await setNonceAsync(box);
          const label = box.querySelector(".zcaptcha-label");
          if (label) {
            label.classList.remove("verified");
            label.setAttribute("aria-checked", "false");
            requestAnimationFrame(() => {
              const canvas = box.querySelector("canvas");
              const storeFp = useCanvasMode && canvas ? storeZapCaptchaFingerprint(canvas) : Promise.resolve();
            
              storeFp.then(async () => {
                if (zapFlags.getFlag("serverMode")) { await zapVerify({ triggerId: triggerEl.id }); }
                
                requestAnimationFrame(() => {
                  label.classList.add("verified");
                  UIOverlayManager.enable(triggerEl);
                  label.setAttribute("aria-checked", "true");
                  tamperWatcher.disconnect();
                  dispatchIfLegit(box, new CustomEvent("zapcaptcha-verified", {
                    detail: { timestamp: Date.now(), id: getStorageName(box) }
                  }));
                });
              });
            });
          }
          setTimeout(() => {
            
            if (!checkHoneypotTraps()) {
              (async () => { await zapLockout("ZapCaptcha honeypot triggered"); })();
              zapMessage("w", "Honeypot triggered");
              return; // If we make it here, lockout is turned off
            }
            
            if (zapFlags.getFlag("lockoutsEnabled") && box.classList.contains("softlocked")) { return; }
          
            onSuccess?.();
          }, DELAYS.submit);
        }, tamperWatcher);
      }, DELAYS.spawn);
    },
    async isVerified(triggerEl) {
      const triggerId = triggerEl.getAttribute("id");
      const box = document.querySelector(`.zcaptcha-box[data-target-id="${triggerId}"]`);
      if (!box) {
        zapMessage("e", "ZapCaptcha failed to find box for trigger:", triggerId); return;
      }

      const ts = parseInt(triggerEl.dataset.zcapVerifiedAt || "0", 10);
      const age = (Date.now() - ts) / 1000;
      const timeoutAttr = box?.getAttribute("data-zcap-timeout");
      const timeoutSec = parseInt(timeoutAttr, 10) || 60;
      return (verifiedMap.get(triggerEl) && age < timeoutSec && await verifyNonceAsync(box));
    },
    clear(triggerEl) {
      const triggerId = triggerEl.getAttribute("id");
      const box = document.querySelector(`.zcaptcha-box[data-target-id="${triggerId}"]`);
      if (!box) {
         zapMessage("e", "ZapCaptcha failed to find box for trigger:", triggerId); return;
      }
    
      clearTimeoutWatcher(triggerEl);
      removeTimeoutMessage(box);
      verifiedMap.delete(triggerEl);
      triggerEl.removeAttribute("data-zcap-verified-at");
      clearNonce(box);
    }
  };
  
  // Lock down each method on ZapCaptcha before freezing it
  for (const key of Object.keys(window.ZapCaptcha)) {
    const val = window.ZapCaptcha[key];
    if (typeof val === "function") {
      Object.defineProperty(window.ZapCaptcha, key, {
        value: val,
        writable: false,
        configurable: false,
        enumerable: true
      });
    }
  }

  // Freeze and harden ZapCaptcha public interface
  Object.setPrototypeOf(window.ZapCaptcha, null);
  Object.freeze(window.ZapCaptcha);
  Object.defineProperty(window, 'ZapCaptcha', { writable: false, configurable: false });

  // Re-enable UI Buttons and standardize captcha boxes
  window.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".zapcaptcha-button").forEach(btn => btn.removeAttribute("disabled"));
  
    insertZapRule(".zcap-brand-text", `
      cursor: pointer !important;
      color: black !important;
      font-size: 13px !important;
      font-family: inherit !important;
      text-decoration: none !important;
    `);
  
    document.querySelectorAll(".zcaptcha-box").forEach((box) => {
      if (!box.dataset.zcapId || box.dataset.zcapId.trim() === "") {
        const uuid = crypto.randomUUID?.() || Math.random().toString(36).slice(2, 10);
        box.dataset.zcapId = `zcid_${uuid}`;
      }
      
      // Lock zcapId
      Object.defineProperty(box.dataset, "zcapId", {
        value: box.dataset.zcapId,
        writable: false,
        configurable: false,
        enumerable: true
      });
      
      // Support compact mode
      if (box.dataset.size === "compact") { box.classList.add("zcaptcha-compact"); }
  
      // Wipe and inject standardized structure
      box.innerHTML = `
        <div class="zcaptcha-left">
          <p class="zcaptcha-label" role="checkbox" aria-checked="false" tabindex="0">
            <span class="label-unverified">🔒 Humans only</span>
            <span class="label-verified" aria-live="polite">✅ I am human</span>
          </p>
        </div>
        <div class="zcaptcha-right">
          <img src="https://zapcaptcha.com/zap.svg" alt="zapcaptcha logo" class="zcaptcha-logo">
          <p class="zname"><span class="zcap-brand-text" data-href="https://zapcaptcha.com">ZapCaptcha</span></p>
          <div class="zcaptcha-terms">
            <a href="https://zapcaptcha.com/privacy" target="_blank">Privacy</a> · <a href="https://zapcaptcha.com/terms" target="_blank">Terms</a>
          </div>
        </div>
      `;
      
      const brand = box.querySelector(".zcap-brand-text");
      if (brand) {
        brand.addEventListener("click", () => {
          window.open(brand.getAttribute("data-href"), "_blank", "noopener");
        });
      }
      
      const label = box.querySelector(".zcaptcha-label");
      if (label) {
        label.addEventListener("keydown", e => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            const triggerId = box.getAttribute("data-target-id");
            const triggerEl = document.getElementById(triggerId);
            if (triggerEl) ZapCaptcha.verify(triggerEl);
          }
        });
      }
    });
  });

  // Need to lock up the UI during challenge
  const UIOverlayManager = (() => {
    let currentOwner = null;
    let overlayEl = null;
  
    function disable(triggerEl) {
      if (!triggerEl || currentOwner === triggerEl) return;
  
      // Remove any existing overlay first
      if (overlayEl) overlayEl.remove();
  
      currentOwner = triggerEl;
      overlayEl = document.createElement("div");
      overlayEl.className = "zcaptcha-overlay";
      overlayEl.setAttribute("aria-hidden", "true");
      overlayEl.addEventListener("click", (e) => e.stopPropagation());
  
      document.body.appendChild(overlayEl);
    }
    
    function softDisable(triggerEl) {
      if (!triggerEl) return;
      triggerEl.dataset.zapUiDisabled = "1";
      triggerEl.setAttribute("aria-disabled", "true");
      triggerEl.setAttribute("disabled", "true");
      triggerEl.style.pointerEvents = "none";
      triggerEl.style.opacity = "0.5";
      triggerEl.style.filter = "grayscale(100%)";
    };
    
    function softEnable(triggerEl) {
      if (!triggerEl) return;
      delete triggerEl.dataset.zapUiDisabled;
      triggerEl.removeAttribute("aria-disabled");
      triggerEl.removeAttribute("disabled");
      triggerEl.style.pointerEvents = "";
      triggerEl.style.opacity = "";
      triggerEl.style.filter = "";
    };
  
    function enable(triggerEl) {
      if (!triggerEl || triggerEl !== currentOwner) return;
  
      if (overlayEl) overlayEl.remove();
      overlayEl = null;
      currentOwner = null;
    }
  
    function forceEnable() {
      // Used when we want to fully clear any active overlay no matter who owns it
      if (overlayEl) overlayEl.remove();
      overlayEl = null;
      currentOwner = null;
    }
  
    function getOwner() {
      return currentOwner;
    }
  
    return {
      disable,
      enable,
      softDisable,
      softEnable,
      forceEnable,
      getOwner
    };
  })();

  // Patch createElement and createElementNS
  function monkeyPatch() {
    if (!zapFlags.getFlag("monkeyPatching")) { return; }
    try {
      const blockedTags = ["script", "iframe", "object", "embed"];
      
      const origCreateElement = Document.prototype.createElement;
      Document.prototype.createElement = function(tagName, options) {
        if (blockedTags.includes(String(tagName).toLowerCase())) {
          zapMessage("w", "Blocked suspicious element creation: ", tagName);
          return origCreateElement.call(this, "div", options);
        }
        return origCreateElement.call(this, tagName, options);
      };
  
      const origCreateElementNS = Document.prototype.createElementNS;
      Document.prototype.createElementNS = function(ns, tagName, options) {
        if (blockedTags.includes(String(tagName).toLowerCase())) {
          zapMessage("w", "Blocked suspicious namespaced element: ", tagName);
          return origCreateElementNS.call(this, ns, "div", options);
        }
        return origCreateElementNS.call(this, ns, tagName, options);
      };
    } catch (err) {
      zapMessage("e", "Injection prevention failed:", err);
    }
  }
  monkeyPatch();
  
  // My attempt to safely block shadow attempts after load
  function plugShadowDOM() {
    if (!zapFlags.getFlag("lockShadow")) return;
    if (!Element.prototype.attachShadow) return;
  
    try {
      const original = Element.prototype.attachShadow;
  
      Object.defineProperty(Element.prototype, 'attachShadow', {
        value: function(init) {
          const allowed = this.dataset.zapOkShadow === "1";
          if (allowed) return original.call(this, init);
          zapMessage("i", "Shadow DOM creation blocked on:", this);
          return null;
        },
        writable: false,
        configurable: false,
      });
    } catch (err) {
      zapMessage("w", "Failed to lock down attachShadow:", err);
    }
  }
  plugShadowDOM();
  
  insertZapRule(".zap-fade-out", `
    transition: opacity 0.3s ease !important;
    opacity: 0 !important;
  `);

  function fadeAndRemove(node) {
    node.classList.add("zap-fade-out");
    setTimeout(() => node.remove(), 300);
  }

  insertZapRule(".zcap-dom-label", `
    font-size: 20px !important;
    color: #606060 !important;
  `);
  
  insertZapRule(".zcap-dom-right", `
    display: flex !important;
    flex-direction: column !important;
    align-items: center !important;
  `);
  
  insertZapRule(".zcap-dom-logo", `
    width: 46px !important;
    height: 46px !important;
  `);
  
  insertZapRule(".zcap-zname", `
    margin: 0 !important;
    padding: 0 !important;
  `);

  // DOM mode is provided for legacy system support
  // Not recommended as a first option on most systems
  function launchZcaptchaDOM(triggerEl, delays, callback, tamperWatcher) {
    const box = document.createElement("div");
    box.className = "zcaptcha-bouncer";
    const checkboxClass = `zc_${crypto.randomUUID().slice(0, 8)}`;
    box.innerHTML = `
      <div class="zcaptcha-left">
        <input type="checkbox" class="${checkboxClass}" disabled aria-hidden="true">
        <span class="zcap-dom-label">I'm not a robot</span>
      </div>
      <div class="zcaptcha-right zcap-dom-right" aria-hidden="true">
        <img src="https://zapcaptcha.com/zap.svg" alt="zapcaptcha logo" class="zcaptcha-logo zcap-dom-logo">
        <p id="zname" class="zcap-zname">ZapCaptcha</p>
        <div class="zcaptcha-terms"><a href="#">Privacy</a> · <a href="#">Terms</a></div>
      </div>
    `;
    document.body.appendChild(box);
    bouncerMap.set(triggerEl, box);
    animateBox(box, triggerEl, callback, delays, tamperWatcher); // Bouncer challenge
  }

  // DOM mode only. I pulled out the game logic into this function.
  function animateBox(box, triggerEl, callback, delays, tamperWatcher) {
    const boundsWidth = document.documentElement.clientWidth;
    let boundsHeight = document.documentElement.clientHeight;
    const width = box.offsetWidth;
    const height = box.offsetHeight;
    const scrollLeft = window.scrollX;
    const scrollTop = window.scrollY;
    
    let visibleWidth, visibleHeight;

    // Turns out some older Android WebViews don't support visualViewport
    if (zapFlags.getFlag("viewportConfined")) {
      visibleWidth = window.visualViewport?.width || window.innerWidth;
      visibleHeight = window.visualViewport?.height || window.innerHeight;
    } else {
      visibleWidth = document.documentElement.scrollWidth;
      visibleHeight = document.documentElement.scrollHeight;
    }

    let x, y;
    
    if (zapFlags.getFlag("viewportConfined")) {    
      x = scrollLeft + getCryptoFloat(0, visibleWidth - width);
      y = scrollTop + getCryptoFloat(0, visibleHeight - height);
    } else {
       x = getCryptoFloat(0, boundsWidth - width);
       y = getCryptoFloat(0, boundsHeight - height);
    }
    let speedScale = 1.0;
    if (isProbablyMobile()) { speedScale = 0.1 };
    let dx = getCryptoFloat(1.5, 3.5) * speedScale;
    let dy = getCryptoFloat(1.5, 3.5) * speedScale;
    let jitterCounter = 0;

    const move = () => {
      jitterCounter++;
      if (jitterCounter % 30 === 0) {
        const speed = getCryptoFloat(1.5, 3.0);
        const angle = getCryptoFloat(0, 2 * Math.PI);
        dx = Math.cos(angle) * speed;
        dy = Math.sin(angle) * speed;
      }

      x += dx;
      y += dy;

      if (zapFlags.getFlag("viewportConfined")) {
        if (x <= scrollLeft || x + box.offsetWidth >= scrollLeft + visibleWidth) { dx = -dx; }
        if (y <= scrollTop || y + box.offsetHeight >= scrollTop + visibleHeight) { dy = -dy; }
      } else {
        if (x <= 0 || x >= boundsWidth - width) { dx = -dx; }
        if (y <= 0 || y >= boundsHeight - height) { dy = -dy; }
      }

      box.style.left = `${x}px`;
      box.style.top = `${y}px`;

      box._raf = requestAnimationFrame(move);
    };

    box.style.position = "absolute";
    box.style.left = `${x}px`;
    box.style.top = `${y}px`;
    move();

    // Check for DOM mutation
    const mo = new MutationObserver(() => {
      if (!document.body.contains(box)) { document.body.appendChild(box); }
    });
    mo.observe(document.body, { childList: true });

    let clicked = false;
    const shownAt = Date.now();

    box.addEventListener("click", function (e) {
      if (clicked || Date.now() - shownAt < delays.click) return;
    
      const rect = box.getBoundingClientRect();
      const clickX = e.clientX - rect.left;
      const clickY = e.clientY - rect.top;
    
      // Define hitbox of the fake checkbox (from HTML layout)
      const boxX = 10;   // relative to .zcaptcha-left padding
      const boxY = 10;   // estimated Y offset of checkbox inside .zcaptcha-left
      const boxSize = 64;
      const hitPadding = 8;
    
      const inBox =
        clickX >= boxX - hitPadding &&
        clickX <= boxX + boxSize + hitPadding &&
        clickY >= boxY - hitPadding &&
        clickY <= boxY + boxSize + hitPadding;
    
      if (!inBox) {
        zapMessage("w", "Click outside DOM CAPTCHA checkbox zone");
        return;
      }
    
      clicked = true;
      cancelAnimationFrame(box._raf);
      mo.disconnect();
      fadeAndRemove(box);
      const overlay = document.querySelector(".zcaptcha-overlay");
      if (overlay) fadeAndRemove(overlay);
      tamperWatcher.disconnect();
      clearTimeoutWatcher(triggerEl);
      removeTimeoutMessage(box);
      setTimeoutWatcher(document.querySelector(`.zcaptcha-box[data-target-id="${triggerEl.id}"]`), triggerEl);
      const triggerExtra = Math.random() < 0.5;
      if (triggerExtra) {
        const triggerId = triggerEl?.id || (box?.getAttribute("data-target-id"));
        if (triggerId) {
          if (zapFlags.getFlag("extraChallenges")) { launchExtraClickShadow(triggerId, box, callback); }
          else { callback?.(); }
        } else {
          zapMessage("e", "launchExtraClickShadow: Missing trigger ID");
        }
      } else {
        callback?.();
      }
    });
  }

  // This is obvious but, canvas mode only
  function launchZcaptchaCanvas(triggerEl, delays, callback, tamperWatcher) {
    const canvas = document.createElement("canvas");
    canvasMap.set(triggerEl, canvas);
    canvas.width = window.innerWidth < 330 ? 280 : window.innerWidth < 360 ? 300 : 330;
    canvas.height = window.innerHeight < 120 ? 90 : 100;
    canvas.style.position = "absolute";
    canvas.style.zIndex = 10000;
    canvas.style.cursor = "pointer";
    canvas.style.maxWidth = "100vw";
    canvas.style.maxHeight = "100vh";
    canvas.style.border = "2px solid cyan";
    canvas.style.borderRadius = "8px";
    document.body.appendChild(canvas);

    const ctx = canvas.getContext("2d");
    const zapImage = new Image();
    zapImage.src = "https://zapcaptcha.com/zap.svg";

    zapImage.onload = function () {
      let x, y;
      const rect = document.documentElement.getBoundingClientRect();
      const scrollLeft = window.scrollX;
      const scrollTop = window.scrollY;
      
      let visibleWidth, visibleHeight;
      
      if (zapFlags.getFlag("viewportConfined")) {
        visibleWidth = window.visualViewport?.width || window.innerWidth;
        visibleHeight = window.visualViewport?.height || window.innerHeight;
      } else {
        visibleWidth = document.documentElement.scrollWidth;
        visibleHeight = document.documentElement.scrollHeight;
      }
      
      if (zapFlags.getFlag("viewportConfined")) {
        x = scrollLeft + getCryptoFloat(0, visibleWidth - canvas.width);
        y = scrollTop + getCryptoFloat(0, visibleHeight - canvas.height);
      } else {
        x = getCryptoFloat(0, Math.max(0, document.documentElement.clientWidth - canvas.width));
        y = getCryptoFloat(0, Math.max(0, window.innerHeight - canvas.height));
      }
      let speedScale = 1.0;
      if (isProbablyMobile()) { speedScale = 0.1 };
      let dx = getCryptoFloat(1.5, 3.5) * speedScale;
      let dy = getCryptoFloat(1.5, 3.5) * speedScale;
      let jitterCounter = 0;

      const drawFrame = () => {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.shadowColor = "rgba(0,0,0,0.1)";
        ctx.shadowBlur = 6;
        ctx.fillStyle = "#fff";
        roundRect(ctx, 0, 0, canvas.width, canvas.height, 8);
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.lineWidth = 2;
        ctx.strokeStyle = "#ccc";
        roundRect(ctx, 0, 0, canvas.width, canvas.height, 8);
        ctx.stroke();

        ctx.strokeStyle = "#666";
        ctx.lineWidth = 1.5;
        ctx.strokeRect(26, 40, 20, 20);

        ctx.font = "18px 'Segoe UI', Tahoma, sans-serif";
        ctx.fillStyle = "#606060";
        ctx.fillText("I'm not a robot", 54, 56);

        ctx.drawImage(zapImage, canvas.width - 75, 7, 52, 52);

        ctx.font = "14px 'Segoe UI', Tahoma, sans-serif";
        ctx.fillStyle = "#000";
        ctx.fillText("ZapCaptcha", canvas.width - 90, 70);

        ctx.font = "12px 'Segoe UI', Tahoma, sans-serif";
        ctx.fillStyle = "#444";
        ctx.fillText("Privacy · Terms", canvas.width - 91, 86);

        jitterCounter++;
        if (jitterCounter % 30 === 0) {
          const speed = getCryptoFloat(1.5, 3.0);
          const angle = getCryptoFloat(0, 2 * Math.PI);
          dx = Math.cos(angle) * speed;
          dy = Math.sin(angle) * speed;
        }

        x += dx;
        y += dy;

        if (zapFlags.getFlag("viewportConfined")) {
          if (x <= scrollLeft || x >= scrollLeft + visibleWidth - canvas.width) { dx = -dx; }
          if (y <= scrollTop || y >= scrollTop + visibleHeight - canvas.height) { dy = -dy; }
        } else {
          if (x <= 0 || x + canvas.width >= window.innerWidth) { dx = -dx; }
          if (y <= 0 || y + canvas.height >= window.innerHeight) { dy = -dy; }
        }

        canvas.style.left = `${x}px`;
        canvas.style.top = `${y}px`;

        canvas._raf = requestAnimationFrame(drawFrame);
      };
      drawFrame();
    };

    const shownAt = Date.now();
    let clicked = false;

    canvas.addEventListener("click", function(e) {
      if (clicked || Date.now() - shownAt < delays.click) { return ; }
      // Adding some anti-bot
      const rect = canvas.getBoundingClientRect();
      const clickX = e.clientX - rect.left;
      const clickY = e.clientY - rect.top;
    
      // Define checkbox bounds with a bit of leeway
      const boxX = 26;
      const boxY = 40;
      const boxSize = 64;
      const hitPadding = 10;
    
      const inBox =
        clickX >= boxX - hitPadding &&
        clickX <= boxX + boxSize + hitPadding &&
        clickY >= boxY - hitPadding &&
        clickY <= boxY + boxSize + hitPadding;
    
      if (!inBox) { return; }
      clicked = true;
      cancelAnimationFrame(canvas._raf);
      fadeAndRemove(canvas);
      const overlay = document.querySelector(".zcaptcha-overlay");
      tamperWatcher.disconnect();
      if (overlay) { fadeAndRemove(overlay); }
      const triggerExtra = Math.random() < 0.5;
      if (triggerExtra) {
        const triggerId = triggerEl?.id || (box?.getAttribute("data-target-id"));
        if (triggerId) {
          if (zapFlags.getFlag("extraChallenges")) { launchExtraClickShadow(triggerId, canvas, callback); }
          else { callback?.(); }
        } else {
          zapMessage("e", "launchExtraClickShadow: Missing trigger ID");
        }
      } else {
        callback?.();
      }
    });

    function roundRect(ctx, x, y, w, h, r) {
      ctx.beginPath();
      ctx.moveTo(x + r, y);
      ctx.lineTo(x + w - r, y);
      ctx.quadraticCurveTo(x + w, y, x + w, y + r);
      ctx.lineTo(x + w, y + h - r);
      ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
      ctx.lineTo(x + r, y + h);
      ctx.quadraticCurveTo(x, y + h, x, y + h - r);
      ctx.lineTo(x, y + r);
      ctx.quadraticCurveTo(x, y, x + r, y);
      ctx.closePath();
    }
  }

  // Performance
  const preload = document.createElement("link");
  preload.rel = "preload";
  preload.as = "image";
  preload.href = "https://zapcaptcha.com/zap.svg";
  document.head.appendChild(preload);
  
  // This check is mostly obsolete at this point
  function probeCheck() {
    const img = new Image();
    Object.defineProperty(img, 'id', {
      get: function () {
        zapMessage("w", "DevTools accessed via console inspection");
        return "zap";
      }
    });
    img.id; // Trigger
  }
  
  function launchExtraClickShadow(triggerId, el, finalCallback) {
    const triggerEl = document.getElementById(triggerId);
    if (triggerEl) {
      clearTimeoutWatcher(triggerEl);
      timeoutMap.delete(triggerEl);
    }
    if (el._raf) cancelAnimationFrame(el._raf);
  
    // Clear existing timeout using triggerId instead of el
    clearTimeoutWatcher(triggerId);
  
    extraMap.set(el, true);
    UIOverlayManager.disable(el);
  
    const host = document.createElement("div");
    host.style.position = "absolute";
    host.style.zIndex = "10002";
    host.dataset.zapOkShadow = "1";
  
    const rect = el.getBoundingClientRect();
    host.style.left = `${rect.left + window.scrollX}px`;
    host.style.top = `${rect.top + window.scrollY}px`;
    host.style.width = `${rect.width}px`;
    host.style.height = `${rect.height}px`;
  
    document.body.appendChild(host);
  
    const mode = Math.random() < 0.5 ? "multi" : "hold";
    const shadowMode = mode === "hold" ? "open" : "closed";
    const shadow = host.attachShadow({ mode: shadowMode });
  
    const container = document.createElement("div");
    container.style.width = "100%";
    container.style.height = "100%";
    container.style.background = "#000";
    container.style.color = "#fff";
    container.style.display = "flex";
    container.style.flexDirection = "column";
    container.style.alignItems = "center";
    container.style.justifyContent = "center";
    container.style.fontSize = "18px";
    container.style.borderRadius = "8px";
    container.style.cursor = "pointer";
    container.style.userSelect = "none";
  
    // Timeout logic — works for all modes
    const timeoutHandle = setTimeout(() => {
      extraMap.delete(el);
      verifiedMap.set(el, false);
  
      const box = document.querySelector(`.zcaptcha-box[data-target-id="${triggerId}"]`);
      if (box) {
        removeTimeoutMessage(box);
        showTimeoutMessage(box, 10);
        box.classList.remove("verified", "pending");
        const label = box.querySelector(".zcaptcha-label");
        if (label) label.classList.remove("verified", "pending");
      
        // Auto-remove timeout message after 5s
        setTimeout(() => {
          removeTimeoutMessage(box);
          box.classList.remove("pending", "verified");
          const label = box.querySelector(".zcaptcha-label");
          if (label) label.classList.remove("pending", "verified");
        }, 5000);
      } else {
        zapMessage("e", "Shadow timeout box not found for:", el.id);
      }
  
      UIOverlayManager.enable(el);
      fadeAndRemove(host);
      fadeAndRemove(el);
  
      document.dispatchEvent(new CustomEvent("zapcaptcha-extra-expired", {
        detail: { triggeredAt: Date.now(), target: el }
      }));
  
      clearTimeoutWatcher(triggerId); // Use ID, not DOM node
    }, 10000);
  
    timeoutMap.set(triggerId, timeoutHandle); // Use ID, not DOM node
  
    if (mode === "multi") {
      container.style.boxShadow = "inset 0 0 0 2px magenta";
      let remaining = Math.floor(getCryptoFloat(1, 7));
      container.textContent = `Click ${remaining} more time${remaining > 1 ? 's' : ''}`;
  
      container.addEventListener("click", (e) => {
        if (!e.isTrusted) return;
        remaining--;
        if (remaining > 0) {
          container.textContent = `Click ${remaining} more time${remaining > 1 ? 's' : ''}`;
        } else {
          clearTimeout(timeoutHandle);
          clearTimeoutWatcher(triggerId);
          host.remove();
          el.remove();
          extraMap.delete(el);
          UIOverlayManager.enable(el);
          finalCallback?.();
          const box = document.querySelector(`.zcaptcha-box[data-target-id="${triggerId}"]`);
          if (box) setTimeoutWatcher(box, el);
        }
      });
  
    } else if (mode === "hold") {
      container.style.boxShadow = "inset 0 0 0 2px orange";
      const holdMs = Math.floor(getCryptoFloat(2, 5)) * 1000;
      let holdTimer = null;
      let countdownInterval = null;
      let holdStart = null;
      let attemptId = 0;
    
      container.textContent = `Hold click for ${holdMs / 1000} seconds`;
    
      const renderCountdown = () => {
        const remaining = holdMs - (Date.now() - holdStart);
        if (remaining > 0) {
          container.textContent = `Holding… ${(remaining / 1000).toFixed(1)}s`;
        } else {
          container.textContent = `Almost there…`;
        }
      };
    
      const startHold = () => {
        attemptId++;
        const thisAttempt = attemptId;
    
        // Reset timers
        if (holdTimer) clearTimeout(holdTimer);
        if (countdownInterval) clearInterval(countdownInterval);
    
        holdStart = Date.now();
        renderCountdown();
    
        countdownInterval = setInterval(() => {
          renderCountdown();
        }, 100);
    
        holdTimer = setTimeout(() => {
          if (thisAttempt !== attemptId) return; // stale
          clearInterval(countdownInterval);
          clearTimeout(timeoutHandle);
          clearTimeoutWatcher(triggerId);
          host.remove();
          el.remove();
          extraMap.delete(el);
          UIOverlayManager.enable(el);
          finalCallback?.();
          const box = document.querySelector(`.zcaptcha-box[data-target-id="${triggerId}"]`);
          if (box) setTimeoutWatcher(box, el);
        }, holdMs);
      };
    
      const cancelHold = () => {
        attemptId++; // Invalidate previous hold
        if (holdTimer) clearTimeout(holdTimer);
        if (countdownInterval) clearInterval(countdownInterval);
        holdTimer = null;
        countdownInterval = null;
        container.textContent = `Hold click for ${holdMs / 1000} seconds (try again)`;
      };
    
      container.style.touchAction = "none";
      container.addEventListener("pointerdown", startHold);
      container.addEventListener("mousedown", startHold);
      container.addEventListener("touchstart", startHold);
    
      container.addEventListener("pointerup", cancelHold);
      container.addEventListener("mouseup", cancelHold);
      container.addEventListener("touchend", cancelHold);
      container.addEventListener("pointerleave", cancelHold);
      container.addEventListener("pointercancel", cancelHold);
    }
    shadow.appendChild(container);
  }
  
  // False positives on mobile and with iframes
  function dimensionCheck() {
    const threshold = 160;
    const wDiff = window.outerWidth - window.innerWidth;
    const hDiff = window.outerHeight - window.innerHeight;
    
    if (wDiff > threshold || hDiff > threshold) { zapMessage("w", "DevTools window dimension anomaly"); }
  }
 
  // Debugger timing anomaly
  function timingCheck() {
    const start = performance.now();
    debugger;
    const end = performance.now();
    
    if (end - start > 50) { zapMessage("w", "Debugger slowdown detected"); }
  }
 
  // Run all checks repeatedly
  if (zapFlags.getFlag("consoleWarnings")) {
    setInterval(() => {
      try {
        probeCheck();
        dimensionCheck();
        timingCheck();
      } catch (e) { zapMessage("e", "Console warning issue: ", e); }
    }, 10000);
  }
})();

/*!
 * ZapCaptcha – Human-first cryptographic CAPTCHA system
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

// Pest quick checks
if (
  navigator.webdriver ||
  window._phantom ||
  window.__nightmare ||
  window.callPhantom
) {
  console.warn("Bot environment detected – access denied.");
  document.body.innerHTML = "Access Denied.";
  throw new Error("Blocked bot environment");
}

try {
  let suspicious = 0;

  if (navigator.plugins.length === 0) suspicious++;
  if (!navigator.languages || navigator.languages.length === 0) suspicious++;

  if (suspicious >= 2) {
    console.warn("Fingerprint strongly resembles a headless or bot environment.");
    document.body.innerHTML = "Access Denied.";
    throw new Error("Multiple fingerprint anomalies");
  }
} catch (e) {
  console.warn("Fingerprint check error:", e);
  // Do not throw, allow page to load for safety due to mobile
}

// Trap config
injectBotTraps({
  delayMs: 3000,
  count: 3
});

// Function that makes life for pests a bit more difficult
function injectBotTraps(config = {}) {
  const trapLinks = [
    { href: "/trap/email.csv", email: "contact@yourdomain.com" },
    { href: "/do-not-enter/hack.txt", email: "admin@yourdomain.com" },
    { href: "/honeypot/secret", email: "info@yourdomain.com" },
    { href: "/.ftp-access/", email: "ftp@yourdomain.com" },
    { href: "/private/tmp.zip", email: "root@yourdomain.com" },
    { href: "/hidden/.env", email: "dev@yourdomain.com" },
    { href: "/logs/access.log", email: "logs@yourdomain.com" }
  ];

  const delay = config.delayMs || 2000;
  const count = config.count || 3;

  // Inject traps here
  function inject() {
    injectTrapLinks();
    addHiddenFormTrap();
    addCanvasNoiseTrap();
    addBeaconTrap();
    monitorDOMMutations();
    checkHumanInteraction();
  }

  // Trap: Inject hidden rotating email links
  function injectTrapLinks() {
    const shuffled = trapLinks.sort(() => 0.5 - Math.random()).slice(0, count);
    shuffled.forEach(({ href, email }) => {
      const a = document.createElement("a");
      a.href = href;
      a.rel = "nofollow";
      a.textContent = email.replace("@", " [at] ").replace(/\./g, " [dot] ");
      a.style.display = "none";
      a.setAttribute("data-honeypot", "true");
      document.body.appendChild(a);
    });
  }

  // Trap: Counters auto-fill bots
  function addHiddenFormTrap() {
    const form = document.createElement("form");
    form.style.position = "absolute";
    form.style.left = "-9999px";
    form.innerHTML = `
      <input type="text" name="full_name" autocomplete="off">
      <input type="email" name="email" autocomplete="off">
    `;
    document.body.appendChild(form);
  }

  // Trap: Detects agent Canvas render capability
  function addCanvasNoiseTrap() {
    const canvas = document.createElement("canvas");
    canvas.width = 10;
    canvas.height = 10;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#f00";
    ctx.fillRect(0, 0, 10, 10);
    try {
      const hash = canvas.toDataURL();
      canvas.setAttribute("data-canvas-hash", hash.slice(-16));
    } catch (e) {
      canvas.setAttribute("data-canvas-error", "true");
    }
    canvas.style.display = "none";
    canvas.setAttribute("data-fingerprint", "true");
    canvas.__counterbot_injected = true; // TODO: Suppress future mutation logs
    document.body.appendChild(canvas);
  }

  // Trap: Inject beacon from memory (no download, no 404)
  function addBeaconTrap() {
    const base64Gif = "R0lGODlhAQABAPAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==";
    const byteString = atob(base64Gif);
    const byteArray = new Uint8Array(byteString.length);
    for (let i = 0; i < byteString.length; i++) {
      byteArray[i] = byteString.charCodeAt(i);
    }
    const blob = new Blob([byteArray], { type: "image/gif" });
    const blobUrl = URL.createObjectURL(blob);

    const img = document.createElement("img");
    img.src = blobUrl;
    img.alt = "beacon trap";
    img.style.display = "none";
    img.setAttribute("data-beacon", "true");

    document.body.appendChild(img);
  }

  // Trap: Detects bots modifying DOM
  function monitorDOMMutations() {
    const observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        if (m.type !== "attributes") continue;
        const target = m.target;
  
        // Suppress known counterbot and ZapCaptcha elements
        const isKnownTrap =
          target.hasAttribute("data-honeypot") ||
          target.hasAttribute("data-beacon") ||
          target.hasAttribute("data-fingerprint") ||
          target.__counterbot_injected === true;
  
        const isZapCaptcha =
          target.closest?.(".zcaptcha-box") ||
          target.className?.toString().includes("zcaptcha") ||
          target.className?.toString().includes("zapcaptcha");
  
        // Allowlist: skip warnings for these
        const allowlist = [
          "[data-honeypot]",
          "[data-beacon]",
          "[data-fingerprint]",
          ".zcaptcha-box",
          ".zcaptcha-overlay",
          ".zapcaptcha-button",
          ".zcaptcha-label",
          ".zcaptcha-right",
          ".zcaptcha-left"
        ];
  
        const isAllowlisted = allowlist.some(sel => {
          try {
            return target.matches?.(sel) || target.closest?.(sel);
          } catch (_) {
            return false;
          }
        });
  
        const isSafeCanvas =
          target.tagName === "CANVAS" &&
          (isKnownTrap || isZapCaptcha || isAllowlisted);
  
        let falsePositives = true // If using ZapCaptcha, logging should be off. Set false to log.
        if (isKnownTrap || isZapCaptcha || isAllowlisted || isSafeCanvas || falsePositives) continue;
  
        console.warn("MutationObserver: Possible DOM tampering detected", m);
      }
    });
  
    observer.observe(document.body, {
      attributes: true,
      subtree: true,
      childList: false
    });
  }

  // Trap: Detect absence of any human interaction
  function checkHumanInteraction() {
    let interacted = false;
    const markInteracted = () => { interacted = true; };

    window.addEventListener("mousemove", markInteracted, { once: true });
    window.addEventListener("touchstart", markInteracted, { once: true });
    window.addEventListener("keydown", markInteracted, { once: true });

    setTimeout(() => {
      if (!interacted) {
        console.warn("No human interaction detected. Possible headless bot.");
      }
    }, 5000);
  }

  // Defer trap injection to idle time or fallback delay
  if (window.requestIdleCallback) {
    requestIdleCallback(inject, { timeout: delay });
  } else {
    setTimeout(inject, delay);
  }
}

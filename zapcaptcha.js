// AT flags
let consoleTamperDetection = false;
let debuggerTimerDetection = false;
let devToolsDetection = false;

window.addEventListener("pageshow", function (e) {
  if (e.persisted) location.reload();
});

const meta = document.querySelector('meta[name="viewport"]');
if (!meta || !/user-scalable\s*=\s*no/i.test(meta.content)) {
  console.warn("ZapCaptcha requires viewport meta tag with 'user-scalable=no' to ensure layout stability on mobile. Falling back to DOM mode, which is less secure and bot-proof.");
}

(function () {
  const verifiedMap = new WeakMap();
  const timeoutMap = new WeakMap();
  
  const isMobile = /Mobi|Android/i.test(navigator.userAgent);
  const viewportMeta = document.querySelector('meta[name="viewport"]');
  const notUserScalable = viewportMeta && /user-scalable\s*=\s*no/i.test(viewportMeta.content);
  const useCanvasMode = !isMobile || (isMobile && notUserScalable);
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

  function generateNonce() {
    return crypto.randomUUID();
  }

  function setNonce(box, nonce) {
    const name = getStorageName(box);
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

  function showTimeoutMessage(box) {
    if (!box) return;
  
    // Remove old message if any
    const oldMsg = box.querySelector(".zcap-timeout-message");
    if (oldMsg) oldMsg.remove();
  
    // Create new message
    const msg = document.createElement("div");
    msg.className = "zcap-timeout-message";
    msg.textContent = "Captcha expired. Please retry.";
  
    // Style it visibly (override if needed)
    msg.style.color = "red";
    msg.style.fontSize = "0.9em";
    msg.style.marginTop = "0px";
    msg.style.marginBottom = "0px";
    msg.style.marginLeft = "0px";
    msg.style.marginRight = "0px";
  
    box.appendChild(msg);
  
    // Dispatch event (optional for advanced users)
    box.dispatchEvent(new CustomEvent("zapcaptcha-expired", {
      detail: { timestamp: Date.now() }
    }));
  }

  function removeTimeoutMessage(box) {
    if (!box) return;
    const msg = box.querySelector(".zcap-timeout-message");
    if (msg) msg.remove();
  }
  
  // Clear any previous timeout for this trigger
  function clearTimeoutWatcher(triggerEl) {
    if (timeoutMap.has(triggerEl)) {
      clearTimeout(timeoutMap.get(triggerEl));
      timeoutMap.delete(triggerEl);
    }
  }

  function setTimeoutWatcher(box, triggerEl) {
    const timeoutAttr = box?.getAttribute("data-zcap-timeout");
    const timeoutSec = parseInt(timeoutAttr, 10);
    if (!timeoutSec || isNaN(timeoutSec) || timeoutSec < 3) return;

    clearTimeoutWatcher(triggerEl);
  
    const timeoutId = setTimeout(() => {
      const trueBox = document.querySelector(`.zcaptcha-box[data-target-id="${triggerEl.id}"]`) || box;
      
      verifiedMap.delete(triggerEl);
      triggerEl.removeAttribute("data-zcap-verified-at");
      clearNonce(trueBox);
  
      let label = box.querySelector(".zcaptcha-label") || box.querySelector(".zcaptcha-left span");
      label?.classList.remove("verified");
  
      showTimeoutMessage(trueBox);
      
      // Auto-remove the expiration message after a delay (optional)
      setTimeout(() => {
        const expiredMsg = trueBox.querySelector(".zcap-timeout-message");
        if (expiredMsg) expiredMsg.remove();
      }, 6000); // Remove after 6s, tweak as needed
      
      // Destroy DOM mode bouncer if exists
      document.querySelectorAll(".zcaptcha-bouncer").forEach(el => el.remove());
      
      // Destroy canvas if exists
      document.querySelectorAll("canvas").forEach(el => {
        if (el._raf) cancelAnimationFrame(el._raf);
        el.remove();
      });
  
      const overlay = document.querySelector(".zcaptcha-overlay");
      if (overlay) overlay.remove();
  
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

  window.ZapCaptcha = {
    submitDelay: 1000,
    verify(triggerEl, onSuccess) {
      const triggerId = triggerEl.getAttribute("id");
      const box = document.querySelector(`.zcaptcha-box[data-target-id="${triggerEl.id}"]`);
      if (!box) {
        console.error("ZapCaptcha failed to find box for trigger:", triggerEl.id);
        return;
      }
      const timestamp = triggerEl.dataset.zcapVerifiedAt;
      const lastNonce = getNonce(box);
      const now = Date.now();

      clearTimeoutWatcher(triggerEl);
      removeTimeoutMessage(box);

     if (verifiedMap.get(triggerEl) && timestamp && lastNonce) {
        const timeoutAttr = box?.getAttribute("data-zcap-timeout");
        const timeoutSec = parseInt(timeoutAttr, 10) || 120;
        const age = (now - parseInt(timestamp)) / 1000;
        if (age < timeoutSec && lastNonce === sessionStorage.getItem(`${NONCE_COOKIE_PREFIX}${getStorageName(box)}`)) {
          return onSuccess?.();
        }
      }

      const form = triggerEl.closest("form");
      if (form && !form.checkValidity()) {
        form.reportValidity();
        return;
      }

      disableUI();
      injectAntiBotTraps();

      const delay = getCryptoFloat(500, 2200);
      setTimeout(() => {
        setTimeoutWatcher(box, triggerEl);
        const launchFunc = useCanvasMode ? launchZcaptchaCanvas : launchZcaptchaDOM;
        launchFunc(triggerEl, () => {
          verifiedMap.set(triggerEl, true);
          triggerEl.dataset.zcapVerifiedAt = Date.now();
          const newNonce = generateNonce();
          setNonce(box, newNonce);
          onSuccess?.();
        });
      }, delay);
    },
    isVerified(triggerEl) {
      const triggerId = triggerEl.getAttribute("id");
      const box = document.querySelector(`.zcaptcha-box[data-target-id="${triggerId}"]`);
      if (!box) {
        console.error("ZapCaptcha failed to find box for trigger:", triggerId);
        return;
      }

      const ts = parseInt(triggerEl.dataset.zcapVerifiedAt || "0", 10);
      const age = (Date.now() - ts) / 1000;
      const timeoutAttr = box?.getAttribute("data-zcap-timeout");
      const timeoutSec = parseInt(timeoutAttr, 10) || 120;
      return (
        verifiedMap.get(triggerEl) &&
        age < timeoutSec &&
        getNonce(box) === sessionStorage.getItem(`${NONCE_COOKIE_PREFIX}${getStorageName(box)}`)
      );
    },
    clear(triggerEl) {
      const triggerId = triggerEl.getAttribute("id");
      const box = document.querySelector(`.zcaptcha-box[data-target-id="${triggerId}"]`);
      if (!box) {
        console.error("ZapCaptcha failed to find box for trigger:", triggerId);
        return;
      }
    
      clearTimeoutWatcher(triggerEl);
      removeTimeoutMessage(box);
      verifiedMap.delete(triggerEl);
      triggerEl.removeAttribute("data-zcap-verified-at");
      clearNonce(box);
    }
  };

  // Freeze ZapCaptcha Object
  Object.freeze(window.ZapCaptcha);
  Object.freeze(window.ZapCaptcha.verify);
  Object.freeze(window.ZapCaptcha.isVerified);
  Object.defineProperty(window, 'ZapCaptcha', { writable: false, configurable: false });

  // Periodic zapcaptcha.js Integrity Check
  (function checkZapCaptchaJS() {
    const meta = document.querySelector('meta[name="zap-integrity"]');
    if (!meta || !meta.content || !meta.content.startsWith("sha256-")) return;
  
    const expected = meta.content.trim();
  
    function performCheck() {
      fetch("zapcaptcha.js")
        .then(r => r.ok ? r.text() : Promise.reject("Failed to fetch zapcaptcha.js"))
        .then(text => sha256(text))
        .then(hash => {
          const actual = "sha256-" + hash;
          if (actual !== expected) {
            document.body.innerHTML = "<h1 style='color:red;text-align:center;padding-top:100px;'>ZapCaptcha Integrity Error</h1>";
            throw new Error(`zapcaptcha.js hash mismatch\nExpected: ${expected}\nActual: ${actual}`);
          }
        })
        .catch(err => {
          console.error("ZapCaptcha integrity check failed:", err);
          document.body.innerHTML = "<h1 style='color:red;text-align:center;padding-top:100px;'>ZapCaptcha Integrity Check Failed</h1>";
        });
    }
  
    // Initial check
    performCheck();
  
    // Re-check every 10 seconds
    setInterval(performCheck, 10000);
  })();

  // SHA-256 Helper
  function sha256(str) {
    const buf = new TextEncoder().encode(str);
    return crypto.subtle.digest("SHA-256", buf).then(hash => {
      return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    });
  }

  // Re-enable UI Buttons and assign unique zcapId to each box
  window.addEventListener("DOMContentLoaded", () => {
    // Re-enable buttons
    document.querySelectorAll(".zapcaptcha-button").forEach(btn => btn.removeAttribute("disabled"));
  
    // Assign unique zcapId to each captcha box
    document.querySelectorAll(".zcaptcha-box").forEach((box) => {
      if (!box.dataset.zcapId || box.dataset.zcapId.trim() === "") {
        const uuid = crypto.randomUUID?.() || Math.random().toString(36).slice(2, 10);
        box.dataset.zcapId = `zcid_${uuid}`;
      }
    });
  });

  function disableUI() {
    const overlay = document.createElement("div");
    overlay.className = "zcaptcha-overlay";
    overlay.setAttribute("aria-hidden", "true");
    overlay.addEventListener("click", (e) => e.stopPropagation());
    document.body.appendChild(overlay);
  }
 
  function preventInjection() {
    try {
      const origCreateElement = Document.prototype.createElement;
      Document.prototype.createElement = function(tagName, options) {
        if (["script", "iframe", "object", "embed"].includes(String(tagName).toLowerCase())) {
          console.warn("Blocked suspicious element creation:", tagName);
          return document.createElement("div");
        }
        return origCreateElement.call(this, tagName, options);
      };
    } catch (err) {
      console.error("Injection prevention failed:", err);
    }
  }
  preventInjection();

  function getCryptoFloat(min, max) {
    const buf = new Uint32Array(1);
    crypto.getRandomValues(buf);
    return min + (buf[0] / 0xffffffff) * (max - min);
  }

  function fadeAndRemove(node) {
    node.style.transition = "opacity 0.3s ease";
    node.style.opacity = "0";
    setTimeout(() => node.remove(), 300);
  }

  function injectAntiBotTraps() {
    const count = Math.floor(getCryptoFloat(1, 4));
    for (let i = 0; i < count; i++) {
      const trap = document.createElement("input");
      trap.type = "checkbox";
      trap.name = `trap_${crypto.randomUUID()}`;
      Object.assign(trap.style, {
        position: "absolute",
        opacity: "0",
        pointerEvents: "none",
        left: `${Math.random() * window.innerWidth}px`,
        top: `${Math.random() * window.innerHeight}px`
      });
      trap.setAttribute("aria-hidden", "true");
      trap.autocomplete = "off";
      trap.tabIndex = -1;
      trap.addEventListener("change", () => {
        alert("❌ Bot activity detected");
        document.body.innerHTML = "<h1 style='color:red;text-align:center;padding-top:100px;'>Access Denied</h1>";
        throw new Error("Honeypot triggered");
      });
      document.body.appendChild(trap);
    }

    for (let i = 0; i < 2; i++) {
      const fake = document.createElement("input");
      fake.type = "text";
      fake.name = `fk_${crypto.randomUUID()}`;
      Object.assign(fake.style, {
        position: "absolute",
        opacity: "0",
        pointerEvents: "none"
      });
      fake.setAttribute("aria-hidden", "true");
      document.body.appendChild(fake);
    }

    const radio1 = document.createElement("input");
    radio1.type = "radio";
    radio1.name = "bot_radio";
    radio1.value = "1";
    radio1.style.opacity = "0";
    radio1.style.position = "absolute";
    radio1.setAttribute("aria-hidden", "true");
    const radio2 = radio1.cloneNode();
    radio2.value = "2";
    document.body.appendChild(radio1);
    document.body.appendChild(radio2);
  }

  function launchZcaptchaDOM(triggerEl, callback) {
    const box = document.createElement("div");
    box.className = "zcaptcha-bouncer";
    const checkboxClass = `zc_${crypto.randomUUID().slice(0, 8)}`;
    box.innerHTML = `
      <div class="zcaptcha-left">
        <input type="checkbox" class="${checkboxClass}" disabled aria-hidden="true">
        <span style="font-size: 20px; color: #606060;">I'm not a robot</span>
      </div>
      <div class="zcaptcha-right" aria-hidden="true" style="display: flex; flex-direction: column; align-items: center;">
        <img src="zap.svg" alt="zapcaptcha logo" class="zcaptcha-logo" style="width: 46px; height: 46px;">
        <p id="zname" style="margin: 0; padding: 0;">ZapCaptcha</p>
        <div class="zcaptcha-terms"><a href="#">Privacy</a> · <a href="#">Terms</a></div>
      </div>
    `;
    document.body.appendChild(box);
    animateBox(box, triggerEl, callback);
  }

  function animateBox(box, triggerEl, callback) {
    const boundsWidth = document.documentElement.clientWidth;
    const boundsHeight = document.documentElement.clientHeight;
    const width = box.offsetWidth;
    const height = box.offsetHeight;

    let x = getCryptoFloat(0, boundsWidth - width);
    let y = getCryptoFloat(0, boundsHeight - height);
    let dx = getCryptoFloat(1.5, 3.5);
    let dy = getCryptoFloat(1.5, 3.5);
    let jitterCounter = 0;

    const move = () => {
      jitterCounter++;
      if (jitterCounter % 30 === 0) {
        const speed = getCryptoFloat(1.5, 4.5);
        const angle = getCryptoFloat(0, 2 * Math.PI);
        dx = Math.cos(angle) * speed;
        dy = Math.sin(angle) * speed;
      }

      x += dx;
      y += dy;

      if (x <= 0 || x >= boundsWidth - width) dx = -dx;
      if (y <= 0 || y >= boundsHeight - height) dy = -dy;

      box.style.left = `${x}px`;
      box.style.top = `${y}px`;

      box._raf = requestAnimationFrame(move);
    };

    box.style.position = "absolute";
    box.style.left = `${x}px`;
    box.style.top = `${y}px`;
    move();

    const mo = new MutationObserver(() => {
      if (!document.body.contains(box)) {
        document.body.appendChild(box);
      }
    });
    mo.observe(document.body, { childList: true });

    let clicked = false;
    const shownAt = Date.now();
    const minDelay = getCryptoFloat(500, 2200);

    box.addEventListener("click", () => {
      if (clicked || Date.now() - shownAt < minDelay) return;
      clicked = true;
      cancelAnimationFrame(box._raf);
      mo.disconnect();
      fadeAndRemove(box);
      const overlay = document.querySelector(".zcaptcha-overlay");
      if (overlay) fadeAndRemove(overlay);
      clearTimeoutWatcher(triggerEl);
      removeTimeoutMessage(box);
      callback?.();
    });
  }

  function launchZcaptchaCanvas(triggerEl, callback) {
    const canvas = document.createElement("canvas");
    canvas.width = window.innerWidth < 330 ? 280 : window.innerWidth < 360 ? 300 : 330;
    canvas.height = window.innerHeight < 120 ? 90 : 100;
    canvas.style.position = "absolute";
    canvas.style.zIndex = 10000;
    canvas.style.cursor = "pointer";
    canvas.style.maxWidth = "100vw";
    canvas.style.maxHeight = "100vh";
    document.body.appendChild(canvas);

    const ctx = canvas.getContext("2d");
    const zapImage = new Image();
    zapImage.src = "zap.svg";

    zapImage.onload = function () {
      let x = getCryptoFloat(0, Math.max(0, window.innerWidth - canvas.width));
      let y = getCryptoFloat(0, Math.max(0, window.innerHeight - canvas.height));
      let dx = getCryptoFloat(1.5, 3.5);
      let dy = getCryptoFloat(1.5, 3.5);
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
          const speed = getCryptoFloat(1.5, 4.5);
          const angle = getCryptoFloat(0, 2 * Math.PI);
          dx = Math.cos(angle) * speed;
          dy = Math.sin(angle) * speed;
        }

        x += dx;
        y += dy;

        if (x <= 0 || x + canvas.width >= window.innerWidth) dx = -dx;
        if (y <= 0 || y + canvas.height >= window.innerHeight) dy = -dy;

        canvas.style.left = `${x}px`;
        canvas.style.top = `${y}px`;

        canvas._raf = requestAnimationFrame(drawFrame);
      };
      drawFrame();
    };

    const shownAt = Date.now();
    const minDelay = getCryptoFloat(500, 2200);
    let clicked = false;

    canvas.addEventListener("click", () => {
      if (clicked || Date.now() - shownAt < minDelay) return;
      clicked = true;
      cancelAnimationFrame(canvas._raf);
      fadeAndRemove(canvas);
      const overlay = document.querySelector(".zcaptcha-overlay");
      if (overlay) fadeAndRemove(overlay);
      callback?.();
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

  const preload = document.createElement("link");
  preload.rel = "preload";
  preload.as = "image";
  preload.href = "zap.svg";
  document.head.appendChild(preload);
  
    (function enforceConsoleSecurity() {
    // Trap 1: Image .id getter trick
    const img = new Image();
    Object.defineProperty(img, 'id', {
      get: function () {
        if (devToolsDetection) {
          document.body.innerHTML = "<h1 style='color:red;text-align:center;padding-top:100px;'>ZapCaptcha Anti-Tamper: DevTools detected. Access denied.</h1>";
          throw new Error("DevTools accessed via console inspection");
        }
      }
    });
 
    // Trap 2: Debugger timing anomaly
    function timingCheck() {
      const start = performance.now();
      debugger;
      const end = performance.now();
      if (end - start > 50) {
        if (debuggerTimerDetection) {
          document.body.innerHTML = "<h1 style='color:red;text-align:center;padding-top:100px;'>ZapCaptcha Anti-Tamper: Debugger timing anomaly detected. Access denied.</h1>";
          throw new Error("Debugger slowdown detected");
        }
      }
    }
 
    // Trap 3: Dimension discrepancy detection
    function dimensionCheck() {
      const threshold = 160;
      const wDiff = window.outerWidth - window.innerWidth;
      const hDiff = window.outerHeight - window.innerHeight;
      if (wDiff > threshold || hDiff > threshold) {
        if (consoleTamperDetection) {
          document.body.innerHTML = "<h1 style='color:red;text-align:center;padding-top:100px;'>ZapCaptcha Anti-Tamper: Console tamper detected. Access denied.</h1>";
          throw new Error("DevTools window dimension anomaly");
        }
      }
    }
 
    // Trap 4: Probe detection via console.log()
    function probeCheck() {
      console.log(img); // Triggers the getter if DevTools is open
    }
 
    // Run all checks repeatedly
    setInterval(() => {
      try {
        probeCheck();
        timingCheck();
        dimensionCheck();
      } catch (e) {
        console.error("Security exception:", e);
      }
    }, 1000);
  })();
  
})();

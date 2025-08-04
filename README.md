<h1 align="center"><strong>⚡ZAPCAPTCHA</strong></h1>                                                                                                                               
<p align="center"><strong>BOT DEFENSE FOR THE MODERN WEB</strong></p>

🔒 ABOUT
ZapCaptcha is a cryptographically verifiable, fully front-end CAPTCHA solution 
designed for zero-trust environments and can even power browser-only static sites.
It includes both interactive and frictionless challenges, anti-bot traps, nonce replay
protection, timeouts, tamper detection, and optional server-mode binding with RSA 
public key signatures.

Built by QVLx  to defend against automated abuse, ZapCaptcha offers extensive 
browser-side protection — and optional server mode for enterprise-grade control.

--------------------------------------------------------------------------------

🚀 FEATURES
• DOM & Canvas fallback CAPTCHA modes
• Nonce-based replay protection using cookies and sessionStorage
• Visual anti-bot bouncer widget with animated traps
• Tamper-resistant architecture with console/debug detection
• Configurable timeout, UI lockout, and session expiry
• Frictionless CAPTCHA mode with background checks
• Full Shadow DOM and CSSOM compatibility
• Optional server mode with RSA signature verification
• Integrity-checked JS and CSS with `sha384-` hashes

--------------------------------------------------------------------------------

🛠️ USAGE
1. Include the ZapCaptcha JS:
   <script type="module" src="https://zapcaptcha.com/zapcaptcha.js"></script>

2. Pass flags through meta tag:
   <meta name="zap-flags" content="allsec = true, lockoutsEnabled = false, vpnCheck = false">

3. Add a ZapCaptcha widget:
   <div class="zcaptcha-box" data-zcap-timeout="30">
     <button class="zapcaptcha-button" disabled>Verify Me</button>
     <div class="verified-label">✅ Verified</div>
   </div>

4. (Optional) Enable server mode:
   <meta name="zap-server-pubkey" content="-----BEGIN PUBLIC KEY-----...">

5. Use the JavaScript API:
   ZapCaptcha.verify(el, callback)
   ZapCaptcha.isVerified(el)
   ZapCaptcha.clear(el)

--------------------------------------------------------------------------------

🔐 SERVER MODE (Optional)
To cryptographically bind verification to a backend, ZapCaptcha can:
• Sign telemetry payloads with ephemeral RSA keys
• Send signed verification and lockout events to your server
• Validate server-issued commands signed with your public key

The backend must implement signature verification and nonce tracking. See `/docs/`
for implementation details.

--------------------------------------------------------------------------------

👨‍💻 LICENSE
Copyright (C) 2025 QVLX LLC

This project is licensed under the GNU General Public License v3.0.
See LICENSE.txt for details.

--------------------------------------------------------------------------------

🌐 Learn more at: https://zapcaptcha.com
🔬 Built by QVLx Labs · https://qvlx.com · #ProtectAndEmpower

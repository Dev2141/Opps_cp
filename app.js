/* ═══════════════════════════════════════════════════════════════
   StegOS Secure Suite — app.js
   Pure browser JS: Web Crypto API, Canvas API, GSAP, Bootstrap 5
   ═══════════════════════════════════════════════════════════════ */

'use strict';

/* ─── Shared Constants ─── */
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const MAGIC       = new Uint8Array([0x53, 0x54, 0x47, 0x31]); // "STG1"
const SALT        = textEncoder.encode("STEG_SALT_2025");
const IV_LEN      = 12;
const PBKDF_ITER  = 65536;

/* ─── App State ─── */
const state = {
  carrierImage:       null,   // HTMLImageElement
  stegoBlob:          null,   // Blob (PNG output)
  stegoDataUrl:       "",
  selectedSecretFile: null,   // File for file-mode
  decodeImageData:    null,   // ImageData for extract
  analyzeImageData:   null,   // ImageData for analyze
  inboxMessages:      [],
  shareQueue:         [],
  secretMode:         'text', // 'text' | 'file'
  currentView:        'dashboard'
};

/* ═══════════════════════════════════════════════════════════════
   NAVIGATION
   ═══════════════════════════════════════════════════════════════ */
function navigateTo(viewName) {
  const views = ['dashboard', 'hide', 'extract', 'share', 'analyze'];
  views.forEach(v => {
    const el = document.getElementById('view-' + v);
    const tab = document.getElementById('tab-' + v);
    if (el) el.classList.remove('active');
    if (tab) tab.classList.remove('active');
  });

  const target = document.getElementById('view-' + viewName);
  const targetTab = document.getElementById('tab-' + viewName);

  if (target) {
    target.classList.add('active');

    // GSAP slide-in animation
    gsap.fromTo(target, { opacity: 0, x: 24 }, { opacity: 1, x: 0, duration: 0.38, ease: 'power2.out' });
  }
  if (targetTab) targetTab.classList.add('active');

  state.currentView = viewName;
  setStatus('info', 'View: ' + viewName.charAt(0).toUpperCase() + viewName.slice(1));
  if (viewName === 'share') {
    shareCheckHealth(false);
  }
}

/* ═══════════════════════════════════════════════════════════════
   CRYPTO — Key Derivation (PBKDF2-SHA256)
   ═══════════════════════════════════════════════════════════════ */
async function deriveKey(password) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw", textEncoder.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: SALT, iterations: PBKDF_ITER, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false, ["encrypt", "decrypt"]
  );
}

/* ─── AES-256-GCM Encrypt → IV || ciphertext ─── */
async function aesEncrypt(password, plain) {
  const key = await deriveKey(password);
  const iv  = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct  = await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, plain);
  const out = new Uint8Array(IV_LEN + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), IV_LEN);
  return out;
}

/* ─── AES-256-GCM Decrypt ─── */
async function aesDecrypt(password, data) {
  if (data.length <= IV_LEN) throw new Error("Cipher payload too short.");
  const key   = await deriveKey(password);
  const iv    = data.slice(0, IV_LEN);
  const ct    = data.slice(IV_LEN);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, ct);
  return new Uint8Array(plain);
}

/* ═══════════════════════════════════════════════════════════════
   PAYLOAD ENVELOPE
   Format: [4 magic][1 type][2 nameLen][2 mimeLen][8 dataLen][name][mime][data]
   ═══════════════════════════════════════════════════════════════ */
function buildEnvelope(type, fileName, mimeType, dataBytes) {
  const nameBytes = textEncoder.encode(fileName || "");
  const mimeBytes = textEncoder.encode(mimeType || "application/octet-stream");
  const total     = 4 + 1 + 2 + 2 + 8 + nameBytes.length + mimeBytes.length + dataBytes.length;
  const out       = new Uint8Array(total);
  let p = 0;
  out.set(MAGIC, p); p += 4;
  out[p++] = type & 0xff;
  out[p++] = (nameBytes.length >> 8) & 0xff; out[p++] = nameBytes.length & 0xff;
  out[p++] = (mimeBytes.length >> 8) & 0xff; out[p++] = mimeBytes.length & 0xff;
  out[p++] = 0; out[p++] = 0; out[p++] = 0; out[p++] = 0;
  out[p++] = (dataBytes.length >>> 24) & 0xff; out[p++] = (dataBytes.length >>> 16) & 0xff;
  out[p++] = (dataBytes.length >>> 8)  & 0xff; out[p++] =  dataBytes.length         & 0xff;
  out.set(nameBytes, p); p += nameBytes.length;
  out.set(mimeBytes, p); p += mimeBytes.length;
  out.set(dataBytes, p);
  return out;
}

function parseEnvelope(bytes) {
  if (bytes.length < 17 || !looksLikeEnvelope(bytes)) throw new Error("Invalid envelope.");
  let p = 4;
  const type    = bytes[p++];
  const nameLen = (bytes[p++] << 8) | bytes[p++];
  const mimeLen = (bytes[p++] << 8) | bytes[p++];
  p += 4; // skip hi 4 bytes of length
  const lo = ((bytes[p++] << 24) >>> 0) | (bytes[p++] << 16) | (bytes[p++] << 8) | bytes[p++];
  const len = lo >>> 0;
  const fileName = textDecoder.decode(bytes.slice(p, p + nameLen)) || "hidden.bin"; p += nameLen;
  const mimeType = textDecoder.decode(bytes.slice(p, p + mimeLen)) || "application/octet-stream"; p += mimeLen;
  const data = bytes.slice(p, p + len);
  return { isFile: type === 1, fileName, mimeType, data };
}

function looksLikeEnvelope(bytes) {
  return bytes.length >= 4 &&
    bytes[0] === 0x53 && bytes[1] === 0x54 && bytes[2] === 0x47 && bytes[3] === 0x31;
}

/* ═══════════════════════════════════════════════════════════════
   LSB STEGANOGRAPHY
   ═══════════════════════════════════════════════════════════════ */
function lsbEmbed(imageData, payload) {
  const full = new Uint8Array(4 + payload.length);
  full[0] = (payload.length >>> 24) & 0xff;
  full[1] = (payload.length >>> 16) & 0xff;
  full[2] = (payload.length >>> 8)  & 0xff;
  full[3] =  payload.length         & 0xff;
  full.set(payload, 4);

  const data     = imageData.data;
  let bitIdx     = 0;
  const totalBits = full.length * 8;

  for (let i = 0; i < data.length && bitIdx < totalBits; i += 4) {
    for (let c = 0; c < 3 && bitIdx < totalBits; c++) {
      const b = (full[(bitIdx / 8) | 0] >> (7 - (bitIdx % 8))) & 1;
      data[i + c] = (data[i + c] & 0xfe) | b;
      bitIdx++;
    }
    data[i + 3] = 255; // lock alpha
  }
}

function lsbExtract(imageData) {
  const data     = imageData.data;
  const maxBytes = Math.floor((data.length * 3) / (4 * 8));
  const raw      = new Uint8Array(maxBytes);
  let bitIdx     = 0;

  for (let i = 0; i < data.length && bitIdx < maxBytes * 8; i += 4) {
    for (let c = 0; c < 3 && bitIdx < maxBytes * 8; c++) {
      raw[(bitIdx / 8) | 0] |= (data[i + c] & 1) << (7 - (bitIdx % 8));
      bitIdx++;
    }
  }

  const len = ((raw[0] << 24) >>> 0) | (raw[1] << 16) | (raw[2] << 8) | raw[3];
  if (len <= 0 || len > raw.length - 4) {
    throw new Error("No hidden data found. Ensure you are using the original stego PNG/BMP output.");
  }
  return raw.slice(4, 4 + len);
}

/* ═══════════════════════════════════════════════════════════════
   STEGO ANALYZER
   ═══════════════════════════════════════════════════════════════ */
function clamp01(v) { return Math.max(0, Math.min(1, v)); }
function entropyTerm(p) { return p <= 0 ? 0 : -p * Math.log2(p); }
function binaryEntropy(p1) { return entropyTerm(1 - p1) + entropyTerm(p1); }

function normalizedChi(freq) {
  let chi = 0, total = 0;
  for (let i = 0; i < 256; i += 2) {
    const a = freq[i], b = freq[i + 1], sum = a + b;
    total += sum;
    if (sum > 0) { const d = a - b; chi += (d * d) / sum; }
  }
  if (total === 0) return 0;
  return clamp01(1 - Math.exp(-6 * (chi / total)));
}

function readStegoLengthHeader(imageData) {
  const data = imageData.data;
  let len = 0, bitCount = 0;
  for (let i = 0; i < data.length && bitCount < 32; i += 4) {
    for (let c = 0; c < 3 && bitCount < 32; c++) {
      len = ((len << 1) | (data[i + c] & 1)) >>> 0;
      bitCount++;
    }
  }
  return len >>> 0;
}

function analyzeStego(imageData) {
  const data = imageData.data;
  const freq = [new Array(256).fill(0), new Array(256).fill(0), new Array(256).fill(0)];
  const ones = [0, 0, 0];
  const bits = [0, 0, 0];
  let prev = -1, transitions = 0, compared = 0;

  for (let i = 0; i < data.length; i += 4) {
    for (let c = 0; c < 3; c++) {
      const v = data[i + c];
      freq[c][v]++;
      const bit = v & 1;
      ones[c] += bit;
      bits[c]++;
      if (prev !== -1) { if (prev !== bit) transitions++; compared++; }
      prev = bit;
    }
  }

  const ratio     = ones.map((v, i) => v / bits[i]);
  const chi       = freq.map(f => normalizedChi(f));
  const totalBits = bits[0] + bits[1] + bits[2];
  const totalOnes = ones[0] + ones[1] + ones[2];
  const entropy   = binaryEntropy(totalOnes / totalBits);
  const transition = compared > 0 ? transitions / compared : 0;
  const avgRatio  = (ratio[0] + ratio[1] + ratio[2]) / 3;

  const maxPayload    = Math.floor((data.length * 3) / (4 * 8)) - 4;
  const headerLength  = readStegoLengthHeader(imageData);
  const headerPlausible = headerLength >= 40 && headerLength <= maxPayload;

  let headerIndicator = headerPlausible ? 1 : 0;
  if (headerPlausible) {
    const sizeRatio = maxPayload > 0 ? headerLength / maxPayload : 0;
    if (sizeRatio > 0.98) headerIndicator *= 0.8;
    if (headerLength < 56) headerIndicator *= 0.85;
  }

  const chiIndicator        = (chi[0] + chi[1] + chi[2]) / 3;
  const balanceIndicator    = clamp01(1 - Math.abs(avgRatio - 0.5) * 2);
  const entropyIndicator    = clamp01(entropy);
  const transitionIndicator = clamp01(1 - Math.abs(transition - 0.5) * 2);

  const confidence = clamp01(
    0.18 * chiIndicator +
    0.07 * balanceIndicator +
    0.05 * entropyIndicator +
    0.05 * transitionIndicator +
    0.65 * headerIndicator
  ) * 100;

  const verdict = confidence >= 72 ? "Likely hidden data" : confidence >= 45 ? "Suspicious" : "Likely clean";
  return { ratio, chi, entropy, transition, confidence, verdict, headerLength, headerPlausible };
}

/* ═══════════════════════════════════════════════════════════════
   HIDE VIEW — Handlers
   ═══════════════════════════════════════════════════════════════ */
function handleHideCarrierDrop(event) {
  event.preventDefault();
  document.getElementById('hide-dropzone').classList.remove('dropzone-hover');
  const file = event.dataTransfer.files[0];
  if (file) loadCarrierImage(file);
}

function handleHideCarrierSelect(input) {
  if (input.files[0]) loadCarrierImage(input.files[0]);
}

function loadCarrierImage(file) {
  const url    = URL.createObjectURL(file);
  const img    = new Image();
  img.onload   = () => {
    state.carrierImage = img;

    const previewArea = document.getElementById('hide-preview-area');
    const previewImg  = document.getElementById('hide-preview-img');
    previewImg.src    = url;
    previewArea.style.display = 'block';
    gsap.fromTo(previewArea, { opacity: 0, y: 12 }, { opacity: 1, y: 0, duration: 0.4, ease: 'power2.out' });

    document.getElementById('hide-img-size').textContent = `${img.width}×${img.height}`;
    const capBytes = Math.floor(img.width * img.height * 3 / 8);
    document.getElementById('hide-img-cap').textContent = formatBytes(capBytes);

    updateRequiredBytes();
    advanceStepper('hide', 1);
    checkHideReady();
    setStatus('info', `Carrier loaded: ${img.width}×${img.height} — capacity ${formatBytes(capBytes)}`);
  };
  img.src = url;
}

function setSecretMode(mode) {
  state.secretMode = mode;
  const textArea = document.getElementById('secret-text-area');
  const fileArea = document.getElementById('secret-file-area');
  const toggleText = document.getElementById('toggle-text');
  const toggleFile = document.getElementById('toggle-file');

  if (mode === 'text') {
    gsap.to(fileArea, { opacity: 0, duration: 0.18, onComplete: () => { fileArea.style.display = 'none'; } });
    textArea.style.display = 'block';
    gsap.fromTo(textArea, { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: 0.25, ease: 'power2.out' });
    toggleText.classList.add('active');
    toggleFile.classList.remove('active');
  } else {
    gsap.to(textArea, { opacity: 0, duration: 0.18, onComplete: () => { textArea.style.display = 'none'; } });
    fileArea.style.display = 'block';
    gsap.fromTo(fileArea, { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: 0.25, ease: 'power2.out' });
    toggleFile.classList.add('active');
    toggleText.classList.remove('active');
  }
  updateRequiredBytes();
  checkHideReady();
}

function handleSecretFileSelect(input) {
  if (input.files[0]) {
    state.selectedSecretFile = input.files[0];
    document.getElementById('secret-file-chip').textContent =
      `${input.files[0].name} (${formatBytes(input.files[0].size)})`;
    updateRequiredBytes();
    advanceStepper('hide', 2);
    checkHideReady();
  }
}

function updateRequiredBytes() {
  let bytes = 0;
  if (state.secretMode === 'text') {
    const txt = document.getElementById('hide-secret-text').value;
    document.getElementById('text-char-count').textContent = txt.length;
    // envelope + encrypt overhead estimate
    bytes = textEncoder.encode(txt).length + 17 + IV_LEN + 16 + 4;
  } else if (state.selectedSecretFile) {
    bytes = state.selectedSecretFile.size + 17 + IV_LEN + 16 + 4;
  }
  const reqEl = document.getElementById('hide-img-req');
  if (reqEl) reqEl.textContent = bytes > 0 ? formatBytes(bytes) : '—';
  checkHideReady();
}

function updatePasswordStrength(prefix) {
  const pw = document.getElementById(prefix + '-password').value;
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw))   score++;
  if (/[^a-zA-Z0-9]/.test(pw)) score++;

  const bar   = document.getElementById(prefix + '-strength-bar');
  const label = document.getElementById(prefix + '-strength-label');

  const pct   = (score / 5) * 100;
  const color = score <= 1 ? '#ff4f6a' : score <= 3 ? '#f5a623' : '#22d671';
  const txt   = score <= 1 ? 'Weak' : score <= 3 ? 'Medium' : 'Strong';

  gsap.to(bar, { width: pct + '%', duration: 0.35, ease: 'power2.out' });
  bar.style.background = color;
  bar.style.boxShadow  = `0 0 8px ${color}`;
  if (label) { label.textContent = pw.length > 0 ? txt : ''; label.style.color = color; }

  if (prefix === 'hide') { advanceStepper('hide', 3); checkHideReady(); }
}

function togglePasswordVisibility(inputId) {
  const input = document.getElementById(inputId);
  const eye   = document.getElementById(inputId.replace('password', 'pw-eye'));
  if (input.type === 'password') {
    input.type = 'text';
    if (eye) { eye.classList.remove('bi-eye'); eye.classList.add('bi-eye-slash'); }
  } else {
    input.type = 'password';
    if (eye) { eye.classList.remove('bi-eye-slash'); eye.classList.add('bi-eye'); }
  }
}

function checkHideReady() {
  const hasImage    = !!state.carrierImage;
  const hasPassword = document.getElementById('hide-password').value.length >= 1;
  const hasSecret   = state.secretMode === 'text'
    ? document.getElementById('hide-secret-text').value.trim().length > 0
    : !!state.selectedSecretFile;

  const btn = document.getElementById('btn-hide-action');
  btn.disabled = !(hasImage && hasPassword && hasSecret);
}

function advanceStepper(view, step) {
  // Mark completed steps and activate current
  for (let i = 1; i <= 4; i++) {
    const el = document.getElementById(`step-${view}-${i}`);
    if (!el) continue;
    el.classList.remove('active', 'completed');
    if (i < step + 1) el.classList.add('completed');
    if (i === step + 1) el.classList.add('active');
    else if (i === 1 && step === 0) el.classList.add('active');

    // Bounce animation on state change
    const circle = el.querySelector('.stepper-circle');
    if (circle && (i === step || i === step + 1)) {
      gsap.fromTo(circle, { scale: 0.8 }, { scale: 1, duration: 0.35, ease: 'back.out(2)' });
    }
  }
}

/* ─── ENCODE PIPELINE ─── */
async function handleEmbed() {
  const password = document.getElementById('hide-password').value;
  const btn      = document.getElementById('btn-hide-action');

  if (!state.carrierImage) { showToast('error', 'No carrier image', 'Upload an image first.'); return; }
  if (!password)           { showToast('error', 'No password', 'Enter an encryption password.'); return; }

  setBtnLoading(btn, true);
  setStatus('info', 'Encoding and encrypting…');

  try {
    // Build payload
    let envelope;
    if (state.secretMode === 'text') {
      const txt = document.getElementById('hide-secret-text').value;
      if (!txt.trim()) throw new Error("Secret text is empty.");
      envelope = buildEnvelope(0, "", "text/plain", textEncoder.encode(txt));
    } else {
      if (!state.selectedSecretFile) throw new Error("No file selected.");
      const arr = new Uint8Array(await state.selectedSecretFile.arrayBuffer());
      envelope  = buildEnvelope(1, state.selectedSecretFile.name, state.selectedSecretFile.type || 'application/octet-stream', arr);
    }

    // Encrypt
    const cipher = await aesEncrypt(password, envelope);

    // Check capacity
    const img      = state.carrierImage;
    const capBytes = Math.floor(img.width * img.height * 3 / 8);
    if (cipher.length + 4 > capBytes) {
      throw new Error(`Carrier image too small. Need ${formatBytes(cipher.length + 4)}, have ${formatBytes(capBytes)}.`);
    }

    // Draw onto hidden canvas
    const canvas  = document.getElementById('workCanvas');
    canvas.width  = img.width;
    canvas.height = img.height;
    const ctx     = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);

    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    lsbEmbed(imgData, cipher);
    ctx.putImageData(imgData, 0, 0);

    // Export as PNG blob
    canvas.toBlob(blob => {
      state.stegoBlob = blob;
      const reader    = new FileReader();
      reader.onload   = e => { state.stegoDataUrl = e.target.result; };
      reader.readAsDataURL(blob);

      // Success UI
      setBtnLoading(btn, false);
      const successArea = document.getElementById('hide-success-area');
      successArea.style.display = 'block';
      gsap.fromTo(successArea, { opacity: 0, y: 14, scale: 0.97 },
        { opacity: 1, y: 0, scale: 1, duration: 0.45, ease: 'back.out(1.4)' });

      gsap.fromTo(document.getElementById('hide-success-banner'),
        { boxShadow: '0 0 0px rgba(34,214,113,0)' },
        { boxShadow: '0 0 24px rgba(34,214,113,0.4)', duration: 0.5, ease: 'power2.out' });

      advanceStepper('hide', 4);
      setStatus('success', 'Message hidden successfully!');
      showToast('success', 'Done!', 'Stego image ready for download.');
    }, 'image/png');

  } catch (err) {
    setBtnLoading(btn, false);
    setStatus('error', 'Error: ' + err.message);
    showToast('error', 'Encoding failed', err.message);
  }
}

function downloadStegoOutput() {
  if (!state.stegoBlob) { showToast('warning', 'No output', 'Generate a stego image first.'); return; }
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(state.stegoBlob);
  a.download = 'stego_output.png';
  a.click();
  URL.revokeObjectURL(a.href);
  showToast('success', 'Downloading', 'stego_output.png is being downloaded.');
}

function loadStegoIntoExtract() {
  if (!state.stegoBlob) { showToast('warning', 'No output', 'Generate a stego image first.'); return; }

  const img    = new Image();
  img.onload   = () => {
    const canvas  = document.getElementById('workCanvas');
    canvas.width  = img.width;
    canvas.height = img.height;
    const ctx     = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    state.decodeImageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    document.getElementById('extract-file-chip').textContent = 'stego_output.png (from Hide tab)';
    navigateTo('extract');
    checkExtractReady();
    showToast('success', 'Loaded', 'Stego image loaded into Extract tab.');
  };
  img.src = state.stegoDataUrl || URL.createObjectURL(state.stegoBlob);
}

/* ═══════════════════════════════════════════════════════════════
   EXTRACT VIEW — Handlers
   ═══════════════════════════════════════════════════════════════ */
function handleExtractImageSelect(input) {
  const file = input.files[0];
  if (!file) return;

  const warnEl = document.getElementById('extract-jpeg-warn');
  if (file.type === 'image/jpeg') {
    warnEl.style.display = 'flex';
    gsap.fromTo(warnEl, { opacity: 0, y: -8 }, { opacity: 1, y: 0, duration: 0.3, ease: 'power2.out' });
  } else {
    warnEl.style.display = 'none';
  }

  document.getElementById('extract-file-chip').textContent =
    `${file.name} (${formatBytes(file.size)})`;

  const img  = new Image();
  const url  = URL.createObjectURL(file);
  img.onload = () => {
    const canvas  = document.getElementById('workCanvas');
    canvas.width  = img.width;
    canvas.height = img.height;
    const ctx     = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    state.decodeImageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    URL.revokeObjectURL(url);
    checkExtractReady();
    advanceStepper('extract', 1);
    setStatus('info', `Stego image loaded: ${img.width}×${img.height}`);
  };
  img.src = url;
}

function checkExtractReady() {
  const hasImage    = !!state.decodeImageData;
  const hasPassword = document.getElementById('extract-password').value.length >= 1;
  document.getElementById('btn-extract-action').disabled = !(hasImage && hasPassword);
}

/* ─── DECODE PIPELINE ─── */
async function handleExtract() {
  const password = document.getElementById('extract-password').value;
  const btn      = document.getElementById('btn-extract-action');
  const pill     = document.getElementById('extract-status-pill');

  if (!state.decodeImageData) { showToast('error', 'No image', 'Upload a stego image first.'); return; }
  if (!password)               { showToast('error', 'No password', 'Enter the decryption password.'); return; }

  setBtnLoading(btn, true);
  setStatus('info', 'Extracting and decrypting…');
  pill.className = 'status-pill';
  pill.innerHTML = '<i class="bi bi-arrow-clockwise me-1"></i> Extracting…';

  // Hide old results
  document.getElementById('extract-result-area').style.display = 'none';
  document.getElementById('extract-text-result').style.display = 'none';
  document.getElementById('extract-file-result').style.display = 'none';

  try {
    const cipher = lsbExtract(state.decodeImageData);
    const plain  = await aesDecrypt(password, cipher);

    let result;
    if (looksLikeEnvelope(plain)) {
      result = parseEnvelope(plain);
    } else {
      // Raw UTF-8 text fallback
      result = { isFile: false, fileName: '', mimeType: 'text/plain', data: plain };
    }

    setBtnLoading(btn, false);
    pill.className = 'status-pill success';
    pill.innerHTML = '<i class="bi bi-check-circle-fill me-1"></i> Extraction successful';

    const resultArea = document.getElementById('extract-result-area');
    resultArea.style.display = 'block';
    gsap.fromTo(resultArea, { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.38, ease: 'power2.out' });

    if (!result.isFile) {
      const textDiv  = document.getElementById('extract-text-result');
      const pre      = document.getElementById('extract-result-text');
      pre.textContent = textDecoder.decode(result.data);
      textDiv.style.display = 'block';
    } else {
      const blob = new Blob([result.data], { type: result.mimeType });
      const objUrl = URL.createObjectURL(blob);

      const fileDiv = document.getElementById('extract-file-result');
      document.getElementById('extract-file-info').innerHTML = `
        <strong>${result.fileName}</strong><br>
        <span class="text-muted">MIME:</span> ${result.mimeType}<br>
        <span class="text-muted">Size:</span> ${formatBytes(result.data.length)}
      `;

      const dlBtn   = document.getElementById('btn-download-extracted');
      dlBtn.onclick = () => {
        const a    = document.createElement('a');
        a.href     = objUrl;
        a.download = result.fileName;
        a.click();
        showToast('success', 'Downloading', result.fileName);
      };
      fileDiv.style.display = 'block';
    }

    advanceStepper('extract', 3);
    setStatus('success', 'Extraction complete!');
    showToast('success', 'Extracted!', 'Hidden content recovered successfully.');

  } catch (err) {
    setBtnLoading(btn, false);
    pill.className = 'status-pill error';
    pill.innerHTML = '<i class="bi bi-x-circle-fill me-1"></i> Extraction failed';

    const resultArea = document.getElementById('extract-result-area');
    resultArea.style.display = 'block';
    resultArea.innerHTML = `<div class="error-banner mt-2"><i class="bi bi-shield-x me-2"></i><strong>Decryption failed:</strong> ${err.message}</div>`;

    setStatus('error', 'Extraction failed: ' + err.message);
    showToast('error', 'Failed', err.message);
  }
}

function copyExtractedText() {
  const txt = document.getElementById('extract-result-text').textContent;
  navigator.clipboard.writeText(txt).then(() => {
    showToast('success', 'Copied!', 'Text copied to clipboard.');
  }).catch(() => {
    showToast('error', 'Copy failed', 'Could not access clipboard.');
  });
}

/* ═══════════════════════════════════════════════════════════════
   SHARE VIEW — Handlers
   ═══════════════════════════════════════════════════════════════ */
function validateMailboxId(id) { return /^[a-zA-Z0-9_-]{3,32}$/.test(id); }

function getShareFields() {
  return {
    server:    document.getElementById('share-server-url').value.trim(),
    mailboxId: document.getElementById('share-mailbox-id').value.trim(),
    passphrase: document.getElementById('share-passphrase').value,
    sender:    document.getElementById('share-sender').value.trim() || 'anonymous'
  };
}

async function shareApiCall(endpoint, body, server) {
  const url = (server || 'http://localhost:8088') + endpoint;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'ngrok-skip-browser-warning': 'true'
    },
    body: JSON.stringify(body)
  });
  return res.json();
}

async function shareRegisterMailbox() {
  const { server, mailboxId, passphrase } = getShareFields();
  if (!validateMailboxId(mailboxId)) {
    showToast('warning', 'Invalid Mailbox ID', 'Must be 3-32 chars: letters, digits, _ or -');
    return;
  }
  setStatus('info', 'Registering mailbox…');
  try {
    const data = await shareApiCall('/api/mailbox/register', { mailboxId, passphrase }, server);
    if (data.ok) {
      showToast('success', 'Registered!', `Mailbox '${mailboxId}' created.`);
      setStatus('success', 'Mailbox registered.');
    } else if (data.message && data.message.includes('already')) {
      showToast('warning', 'Already exists', data.message);
      setStatus('warning', 'Mailbox already exists.');
    } else {
      showToast('error', 'Failed', data.error || data.message || 'Unknown error.');
      setStatus('error', 'Registration failed.');
    }
  } catch (err) {
    showToast('error', 'Connection error', err.message);
    setStatus('error', 'Connection failed.');
  }
}

async function shareSendImage() {
  if (!state.stegoBlob) {
    showToast('warning', 'No stego image', 'Generate a stego image in the Hide tab first.');
    return;
  }
  const { server, mailboxId, passphrase, sender } = getShareFields();
  if (!validateMailboxId(mailboxId)) {
    showToast('warning', 'Invalid Mailbox ID', 'Must be 3-32 chars: letters, digits, _ or -');
    return;
  }

  setStatus('info', 'Converting image for send…');

  // Convert blob to base64
  const reader = new FileReader();
  reader.onload = async e => {
    // Strip data URL prefix
    const b64 = e.target.result.split(',')[1];

    try {
      setStatus('info', 'Sending stego image…');
      const data = await shareApiCall('/api/message/send',
        { mailboxId, passphrase, sender, stegoImageBase64: b64 }, server);

      if (data.ok) {
        showToast('success', 'Sent!', `Message ID: ${data.messageId} (${formatBytes(data.sizeBytes || 0)})`);
        setStatus('success', 'Stego image sent.');
      } else {
        showToast('error', 'Send failed', data.error || 'Unknown error');
        setStatus('error', 'Send failed.');
      }
    } catch (err) {
      showToast('error', 'Connection error', err.message);
      setStatus('error', 'Connection failed.');
    }
  };
  reader.readAsDataURL(state.stegoBlob);
}

async function shareRefreshInbox() {
  const { server, mailboxId, passphrase } = getShareFields();
  if (!validateMailboxId(mailboxId)) {
    showToast('warning', 'Invalid Mailbox ID', 'Must be 3-32 chars: letters, digits, _ or -');
    return;
  }
  setStatus('info', 'Fetching inbox…');
  try {
    const data = await shareApiCall('/api/message/list', { mailboxId, passphrase }, server);
    if (data.ok) {
      state.inboxMessages = data.messages || [];
      renderInbox();
      setStatus('success', `Inbox: ${state.inboxMessages.length} message(s).`);
    } else {
      showToast('error', 'List failed', data.error || 'Unknown error');
      setStatus('error', 'Inbox fetch failed.');
    }
  } catch (err) {
    showToast('error', 'Connection error', err.message);
    setStatus('error', 'Connection failed.');
  }
}

function renderInbox() {
  const list     = document.getElementById('inbox-list');
  const empty    = document.getElementById('inbox-empty');
  const badge    = document.getElementById('inbox-count-badge');
  badge.textContent = `${state.inboxMessages.length} message${state.inboxMessages.length !== 1 ? 's' : ''}`;

  list.innerHTML = '';

  if (state.inboxMessages.length === 0) {
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  state.inboxMessages.forEach((msg, i) => {
    const letter   = (msg.sender || 'A').charAt(0).toUpperCase();
    const dateStr  = msg.timestamp ? new Date(msg.timestamp).toLocaleString() : '—';
    const sizeStr  = formatBytes(msg.sizeBytes || 0);
    const colors   = ['#4f8ef7', '#22d671', '#f5a623', '#ff4f6a', '#a855f7'];
    const color    = colors[i % colors.length];

    const row = document.createElement('div');
    row.className = 'inbox-row';
    row.id        = 'inbox-row-' + msg.messageId;
    row.innerHTML = `
      <div class="inbox-avatar" style="background:linear-gradient(135deg,${color},${color}99);">${letter}</div>
      <div class="inbox-meta">
        <div class="inbox-sender">${escapeHtml(msg.sender || 'anonymous')}</div>
        <div class="inbox-time">${dateStr}</div>
        <div class="inbox-size">${sizeStr}</div>
      </div>
      <div class="inbox-actions">
        <button class="btn-inbox-dl" onclick="shareDownloadMessage('${msg.messageId}')">
          <i class="bi bi-download me-1"></i> Download
        </button>
        <button class="btn-danger-ghost" onclick="shareDeleteMessage('${msg.messageId}')">
          <i class="bi bi-trash me-1"></i>
        </button>
      </div>
    `;
    list.appendChild(row);
    // Stagger animation
    gsap.fromTo(row, { opacity: 0, y: 16 }, { opacity: 1, y: 0, duration: 0.35, delay: i * 0.07, ease: 'power2.out' });
  });
}

async function shareDownloadMessage(messageId) {
  const { server, mailboxId, passphrase } = getShareFields();
  setStatus('info', 'Downloading message…');
  try {
    const data = await shareApiCall('/api/message/download', { mailboxId, passphrase, messageId }, server);
    if (data.ok && data.imageBase64) {
      const bytes  = base64ToBytes(data.imageBase64);
      const blob   = new Blob([bytes], { type: 'image/png' });
      const a      = document.createElement('a');
      a.href       = URL.createObjectURL(blob);
      a.download   = `stego_${messageId}.png`;
      a.click();

      // Also load into extract
      const img  = new Image();
      const url  = URL.createObjectURL(blob);
      img.onload = () => {
        const canvas  = document.getElementById('workCanvas');
        canvas.width  = img.width;
        canvas.height = img.height;
        const ctx     = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);
        state.decodeImageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        document.getElementById('extract-file-chip').textContent = `stego_${messageId}.png`;
        URL.revokeObjectURL(url);
        checkExtractReady();
      };
      img.src = url;

      setStatus('success', 'Message downloaded.');
      showToast('success', 'Downloaded!', 'Stego image saved and loaded into Extract tab.');
    } else {
      showToast('error', 'Download failed', data.error || 'Unknown error');
    }
  } catch (err) {
    showToast('error', 'Connection error', err.message);
  }
}

async function shareDeleteMessage(messageId) {
  const { server, mailboxId, passphrase } = getShareFields();
  setStatus('info', 'Deleting message…');
  try {
    const data = await shareApiCall('/api/message/delete', { mailboxId, passphrase, messageId }, server);
    if (data.ok) {
      const row = document.getElementById('inbox-row-' + messageId);
      if (row) {
        gsap.to(row, { opacity: 0, x: -24, height: 0, marginBottom: 0, padding: 0,
          duration: 0.35, ease: 'power2.in', onComplete: () => row.remove() });
      }
      state.inboxMessages = state.inboxMessages.filter(m => m.messageId !== messageId);
      const badge = document.getElementById('inbox-count-badge');
      badge.textContent = `${state.inboxMessages.length} message${state.inboxMessages.length !== 1 ? 's' : ''}`;
      setStatus('success', 'Message deleted.');
      showToast('success', 'Deleted', 'Message removed from mailbox.');
    } else {
      showToast('error', 'Delete failed', data.error || 'Unknown error');
    }
  } catch (err) {
    showToast('error', 'Connection error', err.message);
  }
}

/* ═══════════════════════════════════════════════════════════════
   ANALYZE VIEW — Handlers
   ═══════════════════════════════════════════════════════════════ */
const SHARE_API_BASE = '/share-api';

function getShareFields() {
  return {
    mailboxId: document.getElementById('share-mailbox-id').value.trim(),
    passphrase: document.getElementById('share-passphrase').value,
    sender: document.getElementById('share-sender').value.trim() || 'anonymous'
  };
}

async function shareApiCall(endpoint, body = null, options = {}) {
  const method = options.method || 'POST';
  const request = {
    method,
    headers: {
      'ngrok-skip-browser-warning': 'true'
    }
  };

  if (body !== null) {
    request.headers['Content-Type'] = 'application/json';
    request.body = JSON.stringify(body);
  }

  try {
    const res = await fetch(SHARE_API_BASE + endpoint, request);
    let data = {};
    try {
      data = await res.json();
    } catch (err) {
      if (res.ok) throw new Error('Share server returned an unreadable response.');
    }
    if (!res.ok && !data.error) data.error = `Share request failed (${res.status}).`;
    if (typeof data.ok !== 'boolean') data.ok = res.ok;
    return data;
  } catch (err) {
    throw new Error('Share server is offline or the public tunnel expired.');
  }
}

function setShareConnectionState(mode, text) {
  const pill = document.getElementById('share-connection-pill');
  const label = document.getElementById('share-connection-text');
  if (!pill || !label) return;
  pill.className = 'share-connection-pill share-connection-pill--' + mode;
  label.textContent = text;
}

function updateSharePublicLink() {
  const input = document.getElementById('share-public-link');
  const hint = document.getElementById('share-public-hint');
  if (!input || !hint) return;

  if (window.NGROK_URL) {
    input.value = window.NGROK_URL;
    hint.textContent = 'Share this public app link with the receiver so they open the same page.';
  } else {
    input.value = window.location.origin;
    hint.textContent = 'Local-only mode right now. Start server.py with ngrok to share this page publicly.';
  }
}

async function copySharePublicLink() {
  const input = document.getElementById('share-public-link');
  if (!input) return;
  try {
    await navigator.clipboard.writeText(input.value);
    showToast('success', 'Copied!', 'Share link copied to clipboard.');
  } catch (err) {
    showToast('error', 'Copy failed', 'Could not copy the share link.');
  }
}

async function shareCheckHealth(notify = false) {
  setShareConnectionState('checking', 'Checking connection...');
  try {
    const data = await shareApiCall('/health', null, { method: 'GET' });
    if (data.ok) {
      const label = window.NGROK_URL ? 'Public app ready.' : 'Local mode ready.';
      setShareConnectionState('online', label);
      if (notify) showToast('success', 'Share online', label);
      return true;
    }
    throw new Error(data.error || 'Share server is unavailable.');
  } catch (err) {
    setShareConnectionState('offline', 'Offline or tunnel expired.');
    if (notify) showToast('error', 'Share offline', err.message);
    return false;
  }
}

function updateShareQueueBadge() {
  const badge = document.getElementById('share-queue-count-badge');
  const sendBtn = document.getElementById('share-send-all-btn');
  if (badge) badge.textContent = `${state.shareQueue.length} queued`;
  if (sendBtn) sendBtn.disabled = state.shareQueue.length === 0;
}

function renderShareQueue() {
  const list = document.getElementById('share-queue-list');
  const empty = document.getElementById('share-queue-empty');
  if (!list || !empty) return;

  list.innerHTML = '';
  updateShareQueueBadge();

  if (state.shareQueue.length === 0) {
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  state.shareQueue.forEach((item, index) => {
    const row = document.createElement('div');
    row.className = 'share-queue-item';
    row.innerHTML = `
      <img class="share-queue-thumb" src="${item.previewUrl}" alt="${escapeHtml(item.fileName)}">
      <div class="share-queue-meta">
        <div class="share-queue-name">${escapeHtml(item.fileName)}</div>
        <div class="share-queue-sub">${escapeHtml(item.sourceLabel)} - ${formatBytes(item.sizeBytes)}</div>
      </div>
      <button class="btn-danger-ghost" type="button" onclick="removeShareQueueItem('${item.id}')">
        <i class="bi bi-x-lg"></i>
      </button>
    `;
    list.appendChild(row);
    gsap.fromTo(row, { opacity: 0, y: 12 }, { opacity: 1, y: 0, duration: 0.24, delay: index * 0.04, ease: 'power2.out' });
  });
}

function removeShareQueueItem(id) {
  state.shareQueue = state.shareQueue.filter(item => item.id !== id);
  renderShareQueue();
}

async function blobToDataUrl(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error('Could not read image.'));
    reader.readAsDataURL(blob);
  });
}

async function addShareAttachmentFromBlob(blob, fileName, sourceLabel) {
  const dataUrl = await blobToDataUrl(blob);
  state.shareQueue.push({
    id: crypto.randomUUID ? crypto.randomUUID() : ('share_' + Date.now() + '_' + Math.random().toString(16).slice(2)),
    fileName,
    contentType: blob.type || 'image/png',
    imageBase64: dataUrl.split(',')[1],
    previewUrl: dataUrl,
    sizeBytes: blob.size || 0,
    sourceLabel
  });
  renderShareQueue();
}

async function handleShareAttachmentSelect(input) {
  const files = Array.from(input.files || []);
  if (files.length === 0) return;

  try {
    for (const file of files) {
      if (!file.type.startsWith('image/')) continue;
      await addShareAttachmentFromBlob(file, file.name, 'Manual upload');
    }
    showToast('success', 'Images added', `${files.length} image${files.length !== 1 ? 's' : ''} queued for sending.`);
  } catch (err) {
    showToast('error', 'Add failed', err.message);
  } finally {
    input.value = '';
  }
}

async function shareAddCurrentStego() {
  if (!state.stegoBlob) {
    showToast('warning', 'No Hide output', 'Generate a stego image in the Hide tab first.');
    return;
  }

  try {
    await addShareAttachmentFromBlob(state.stegoBlob, `stego_${Date.now()}.png`, 'Hide output');
    showToast('success', 'Queued', 'Current Hide output added to Send.');
  } catch (err) {
    showToast('error', 'Add failed', err.message);
  }
}

async function shareRegisterMailbox() {
  const { mailboxId, passphrase } = getShareFields();
  if (!validateMailboxId(mailboxId)) {
    showToast('warning', 'Invalid Mailbox ID', 'Must be 3-32 chars: letters, digits, _ or -');
    return;
  }

  setStatus('info', 'Registering mailbox...');
  try {
    const data = await shareApiCall('/api/mailbox/register', { mailboxId, passphrase });
    if (data.ok) {
      showToast('success', 'Registered!', `Mailbox '${mailboxId}' created.`);
      setStatus('success', 'Mailbox registered.');
    } else if (data.message && data.message.includes('already')) {
      showToast('warning', 'Already exists', data.message);
      setStatus('warning', 'Mailbox already exists.');
    } else {
      showToast('error', 'Failed', data.error || data.message || 'Unknown error.');
      setStatus('error', 'Registration failed.');
    }
  } catch (err) {
    showToast('error', 'Connection error', err.message);
    setStatus('error', 'Connection failed.');
  }
}

async function shareSendBatch() {
  const btn = document.getElementById('share-send-all-btn');
  const { mailboxId, passphrase, sender } = getShareFields();
  if (!validateMailboxId(mailboxId)) {
    showToast('warning', 'Invalid Mailbox ID', 'Must be 3-32 chars: letters, digits, _ or -');
    return;
  }
  if (state.shareQueue.length === 0) {
    showToast('warning', 'No images queued', 'Add images to the Send section first.');
    return;
  }

  setBtnLoading(btn, true);
  setStatus('info', 'Sending queued images...');
  try {
    const data = await shareApiCall('/api/message/send-batch', {
      mailboxId,
      passphrase,
      sender,
      images: state.shareQueue.map(item => ({
        fileName: item.fileName,
        contentType: item.contentType,
        imageBase64: item.imageBase64
      }))
    });

    if (data.ok) {
      const sentCount = data.count || state.shareQueue.length;
      state.shareQueue = [];
      renderShareQueue();
      await shareRefreshInbox(false);
      showToast('success', 'Sent!', `${sentCount} image${sentCount !== 1 ? 's' : ''} delivered to the mailbox.`);
      setStatus('success', 'Images sent successfully.');
    } else {
      showToast('error', 'Send failed', data.error || 'Unknown error');
      setStatus('error', 'Send failed.');
    }
  } catch (err) {
    showToast('error', 'Connection error', err.message);
    setStatus('error', 'Connection failed.');
  } finally {
    setBtnLoading(btn, false);
  }
}

async function shareRefreshInbox(showToastOnSuccess = true) {
  const btn = document.getElementById('share-refresh-btn');
  const { mailboxId, passphrase } = getShareFields();
  if (!validateMailboxId(mailboxId)) {
    showToast('warning', 'Invalid Mailbox ID', 'Must be 3-32 chars: letters, digits, _ or -');
    return;
  }

  setBtnLoading(btn, true);
  setStatus('info', 'Fetching received images...');
  try {
    const data = await shareApiCall('/api/message/list', { mailboxId, passphrase });
    if (data.ok) {
      state.inboxMessages = data.messages || [];
      renderInbox();
      setStatus('success', `Receive: ${state.inboxMessages.length} image(s).`);
      if (showToastOnSuccess) {
        showToast('success', 'Receive updated', `${state.inboxMessages.length} image${state.inboxMessages.length !== 1 ? 's' : ''} in the mailbox.`);
      }
    } else {
      showToast('error', 'Refresh failed', data.error || 'Unknown error');
      setStatus('error', 'Receive refresh failed.');
    }
  } catch (err) {
    showToast('error', 'Connection error', err.message);
    setStatus('error', 'Connection failed.');
  } finally {
    setBtnLoading(btn, false);
  }
}

function renderInbox() {
  const list = document.getElementById('receive-list');
  const empty = document.getElementById('receive-empty');
  const badge = document.getElementById('receive-count-badge');
  if (!list || !empty || !badge) return;

  badge.textContent = `${state.inboxMessages.length} image${state.inboxMessages.length !== 1 ? 's' : ''}`;
  list.innerHTML = '';

  if (state.inboxMessages.length === 0) {
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  state.inboxMessages.forEach((msg, index) => {
    const previewSrc = msg.previewBase64
      ? `data:${msg.contentType || 'image/png'};base64,${msg.previewBase64}`
      : '';
    const dateStr = msg.timestamp ? new Date(msg.timestamp).toLocaleString() : '-';

    const card = document.createElement('div');
    card.className = 'receive-card';
    card.id = 'receive-card-' + msg.messageId;
    card.innerHTML = `
      <div class="receive-card-preview">
        ${previewSrc
          ? `<img src="${previewSrc}" alt="${escapeHtml(msg.fileName || 'Received image')}">`
          : '<div class="receive-card-fallback"><i class="bi bi-image"></i></div>'}
      </div>
      <div class="receive-card-body">
        <div class="receive-card-name">${escapeHtml(msg.fileName || (`stego_${msg.messageId}.png`))}</div>
        <div class="receive-card-meta">${escapeHtml(msg.sender || 'anonymous')} - ${dateStr}</div>
        <div class="receive-card-meta">${formatBytes(msg.sizeBytes || 0)}</div>
      </div>
      <div class="receive-card-actions">
        <button class="btn-inbox-dl" type="button" onclick="shareDownloadMessage('${msg.messageId}')">
          <i class="bi bi-download me-1"></i> Download
        </button>
        <button class="btn-danger-ghost" type="button" onclick="shareDeleteMessage('${msg.messageId}')">
          <i class="bi bi-trash me-1"></i> Delete
        </button>
      </div>
    `;
    list.appendChild(card);
    gsap.fromTo(card, { opacity: 0, y: 16 }, { opacity: 1, y: 0, duration: 0.28, delay: index * 0.05, ease: 'power2.out' });
  });
}

function loadBlobIntoExtract(blob, fileName) {
  const img = new Image();
  const url = URL.createObjectURL(blob);
  img.onload = () => {
    const canvas = document.getElementById('workCanvas');
    canvas.width = img.width;
    canvas.height = img.height;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    state.decodeImageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    document.getElementById('extract-file-chip').textContent = fileName;
    URL.revokeObjectURL(url);
    checkExtractReady();
  };
  img.src = url;
}

async function shareDownloadMessage(messageId) {
  const { mailboxId, passphrase } = getShareFields();
  setStatus('info', 'Downloading image...');
  try {
    const data = await shareApiCall('/api/message/download', { mailboxId, passphrase, messageId });
    if (data.ok && data.imageBase64) {
      const fileName = data.fileName || `stego_${messageId}.png`;
      const bytes = base64ToBytes(data.imageBase64);
      const blob = new Blob([bytes], { type: data.contentType || 'image/png' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      a.click();
      URL.revokeObjectURL(url);

      loadBlobIntoExtract(blob, fileName);
      setStatus('success', 'Image downloaded.');
      showToast('success', 'Downloaded!', 'Image saved and loaded into Extract.');
    } else {
      showToast('error', 'Download failed', data.error || 'Unknown error');
    }
  } catch (err) {
    showToast('error', 'Connection error', err.message);
  }
}

async function shareDeleteMessage(messageId) {
  const { mailboxId, passphrase } = getShareFields();
  setStatus('info', 'Deleting image...');
  try {
    const data = await shareApiCall('/api/message/delete', { mailboxId, passphrase, messageId });
    if (data.ok) {
      state.inboxMessages = state.inboxMessages.filter(msg => msg.messageId !== messageId);
      renderInbox();
      setStatus('success', 'Image deleted.');
      showToast('success', 'Deleted', 'Image removed from the mailbox.');
    } else {
      showToast('error', 'Delete failed', data.error || 'Unknown error');
    }
  } catch (err) {
    showToast('error', 'Connection error', err.message);
  }
}

function handleAnalyzeImageSelect(input) {
  const file = input.files[0];
  if (!file) return;
  document.getElementById('analyze-file-chip').textContent =
    `${file.name} (${formatBytes(file.size)})`;

  const img  = new Image();
  const url  = URL.createObjectURL(file);
  img.onload = () => {
    const canvas  = document.getElementById('workCanvas');
    canvas.width  = img.width;
    canvas.height = img.height;
    const ctx     = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    state.analyzeImageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    URL.revokeObjectURL(url);
    document.getElementById('btn-analyze-action').disabled = false;
    setStatus('info', `Analyze image loaded: ${img.width}×${img.height}`);
  };
  img.src = url;
}

async function handleAnalyze() {
  if (!state.analyzeImageData) { showToast('error', 'No image', 'Upload an image first.'); return; }

  const btn = document.getElementById('btn-analyze-action');
  setBtnLoading(btn, true);
  setStatus('info', 'Running statistical analysis…');

  // Small timeout so UI can update
  await new Promise(r => setTimeout(r, 60));

  try {
    const res = analyzeStego(state.analyzeImageData);

    setBtnLoading(btn, false);
    setStatus('success', `Analysis complete — ${res.verdict} (${res.confidence.toFixed(1)}% confidence)`);

    showAnalyzeResults(res);
  } catch (err) {
    setBtnLoading(btn, false);
    setStatus('error', 'Analysis error: ' + err.message);
    showToast('error', 'Analysis failed', err.message);
  }
}

function showAnalyzeResults(res) {
  const resultsEl = document.getElementById('analyze-results');
  resultsEl.style.display = 'block';
  gsap.fromTo(resultsEl, { opacity: 0, y: 20 }, { opacity: 1, y: 0, duration: 0.45, ease: 'power2.out' });

  // Verdict card
  const verdictCard = document.getElementById('metric-verdict-card');
  const verdictVal  = document.getElementById('metric-verdict-val');
  verdictCard.classList.remove('danger', 'warning', 'success');
  verdictVal.textContent = res.verdict;
  if (res.verdict === 'Likely hidden data') {
    verdictCard.classList.add('danger');
    verdictVal.style.color = '#ff4f6a';
  } else if (res.verdict === 'Suspicious') {
    verdictCard.classList.add('warning');
    verdictVal.style.color = '#f5a623';
  } else {
    verdictCard.classList.add('success');
    verdictVal.style.color = '#22d671';
  }

  // Confidence
  const confPct = res.confidence.toFixed(2);
  document.getElementById('metric-confidence-val').textContent = confPct + '%';
  const confBar  = document.getElementById('metric-confidence-bar');
  const confColor = res.confidence >= 72 ? '#ff4f6a' : res.confidence >= 45 ? '#f5a623' : '#22d671';
  confBar.style.background = confColor;
  gsap.to(confBar, { width: confPct + '%', duration: 0.7, ease: 'power2.out' });

  // LSB
  document.getElementById('metric-lsb-val').textContent =
    `${res.ratio[0].toFixed(4)} / ${res.ratio[1].toFixed(4)} / ${res.ratio[2].toFixed(4)}`;

  // Chi
  document.getElementById('metric-chi-val').textContent =
    `${res.chi[0].toFixed(4)} / ${res.chi[1].toFixed(4)} / ${res.chi[2].toFixed(4)}`;

  // Entropy
  document.getElementById('metric-entropy-val').textContent = res.entropy.toFixed(6);

  // Transitions / Header
  const hdrStr = res.headerPlausible
    ? `${res.headerLength.toLocaleString()} bytes (plausible)`
    : `${res.headerLength.toLocaleString()} (not plausible)`;
  document.getElementById('metric-trans-val').textContent =
    `${res.transition.toFixed(4)} | hdr=${hdrStr}`;

  // Count-up animation for metric values
  const cards = document.querySelectorAll('#metric-cards-row .metric-card');
  cards.forEach((card, i) => {
    gsap.fromTo(card, { opacity: 0, y: 20, scale: 0.96 },
      { opacity: 1, y: 0, scale: 1, duration: 0.4, delay: i * 0.07, ease: 'back.out(1.3)' });
  });
}

/* ═══════════════════════════════════════════════════════════════
   TOAST NOTIFICATIONS
   ═══════════════════════════════════════════════════════════════ */
const TOAST_ICONS = {
  success: '<i class="bi bi-check-circle-fill toast-icon"></i>',
  warning: '<i class="bi bi-exclamation-triangle-fill toast-icon"></i>',
  error:   '<i class="bi bi-x-circle-fill toast-icon"></i>',
  info:    '<i class="bi bi-info-circle-fill toast-icon"></i>'
};

function showToast(type, title, message) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `stegos-toast ${type}`;
  toast.innerHTML = `
    ${TOAST_ICONS[type] || TOAST_ICONS.info}
    <div class="toast-body">
      <div class="toast-title">${escapeHtml(title)}</div>
      <div class="toast-msg">${escapeHtml(message)}</div>
    </div>
    <button class="toast-close" onclick="dismissToast(this.parentElement)">
      <i class="bi bi-x"></i>
    </button>
  `;
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));

  // Auto-dismiss after 4s
  setTimeout(() => dismissToast(toast), 4000);
}

function dismissToast(toast) {
  if (!toast || !toast.parentElement) return;
  toast.classList.add('hiding');
  setTimeout(() => { if (toast.parentElement) toast.remove(); }, 350);
}

/* ═══════════════════════════════════════════════════════════════
   STATUS BAR
   ═══════════════════════════════════════════════════════════════ */
function setStatus(type, text) {
  const dot  = document.getElementById('status-dot');
  const txt  = document.getElementById('status-text');

  const colorMap = {
    info:    '#4f8ef7',
    success: '#22d671',
    warning: '#f5a623',
    error:   '#ff4f6a'
  };
  const color = colorMap[type] || colorMap.info;

  gsap.to(dot, { backgroundColor: color, boxShadow: `0 0 8px ${color}`, duration: 0.3 });
  gsap.to(txt, { opacity: 0, duration: 0.12, onComplete: () => {
    txt.textContent = text;
    gsap.to(txt, { opacity: 1, duration: 0.18 });
  }});
}

/* ═══════════════════════════════════════════════════════════════
   BUTTON LOADING STATE
   ═══════════════════════════════════════════════════════════════ */
function setBtnLoading(btn, loading) {
  const btnText    = btn.querySelector('.btn-text');
  const btnSpinner = btn.querySelector('.btn-spinner');
  if (loading) {
    if (btnText)    btnText.classList.add('d-none');
    if (btnSpinner) btnSpinner.classList.remove('d-none');
    btn.disabled = true;
  } else {
    if (btnText)    btnText.classList.remove('d-none');
    if (btnSpinner) btnSpinner.classList.add('d-none');
    btn.disabled = false;
  }
}

/* ═══════════════════════════════════════════════════════════════
   PARTICLE BACKGROUND
   ═══════════════════════════════════════════════════════════════ */
function initParticles() {
  const canvas = document.getElementById('particleCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H, particles = [];

  const resize = () => {
    const parent = canvas.parentElement;
    W = canvas.width  = parent.offsetWidth;
    H = canvas.height = parent.offsetHeight;
  };

  const PARTICLE_COUNT = 80;
  const colors = ['rgba(79,142,247,', 'rgba(37,99,235,', 'rgba(34,214,113,'];

  function spawnParticle() {
    const color = colors[Math.floor(Math.random() * colors.length)];
    return {
      x:  Math.random() * (W || 1200),
      y:  Math.random() * (H || 800),
      vx: (Math.random() - 0.5) * 0.35,
      vy: (Math.random() - 0.5) * 0.35,
      r:  Math.random() * 1.5 + 0.5,
      a:  Math.random() * 0.5 + 0.1,
      color
    };
  }

  resize();
  particles = Array.from({ length: PARTICLE_COUNT }, spawnParticle);
  window.addEventListener('resize', () => { resize(); particles = Array.from({ length: PARTICLE_COUNT }, spawnParticle); });

  function tick() {
    ctx.clearRect(0, 0, W, H);

    // Draw connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx   = particles[i].x - particles[j].x;
        const dy   = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          const alpha = (1 - dist / 120) * 0.12;
          ctx.strokeStyle = `rgba(79,142,247,${alpha})`;
          ctx.lineWidth = 0.6;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }

    // Draw particles
    particles.forEach(p => {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0)  p.x = W;
      if (p.x > W)  p.x = 0;
      if (p.y < 0)  p.y = H;
      if (p.y > H)  p.y = 0;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = p.color + p.a + ')';
      ctx.fill();
    });

    requestAnimationFrame(tick);
  }

  tick();
}

/* ═══════════════════════════════════════════════════════════════
   DASHBOARD ANIMATIONS
   ═══════════════════════════════════════════════════════════════ */
function initDashboard() {
  gsap.set(['#hero-title','#hero-subtitle','#hero-badge','#hero-underline',
             '#stat-ribbon .stat-pill','#action-cards .feature-card','.how-step','.tech-item'],
    { opacity: 0 });

  gsap.to('#hero-badge',      { opacity: 1, y: 0, duration: 0.4, ease: 'power2.out', delay: 0.05 });
  gsap.fromTo('#hero-title',  { y: 20, scale: 0.97 }, { opacity: 1, y: 0, scale: 1, duration: 0.5, ease: 'power3.out', delay: 0.1 });
  gsap.to('#hero-subtitle',   { opacity: 1, duration: 0.4, ease: 'power2.out', delay: 0.2 });
  gsap.fromTo('#hero-underline', { width: 0 }, { opacity: 1, width: '80px', duration: 0.5, ease: 'power2.out', delay: 0.25 });

  gsap.fromTo('#stat-ribbon .stat-pill',
    { y: 10, scale: 0.92 },
    { opacity: 1, y: 0, scale: 1, duration: 0.35, stagger: 0.07, ease: 'back.out(1.4)', delay: 0.3 }
  );

  gsap.fromTo('#action-cards .feature-card',
    { y: 22 },
    { opacity: 1, y: 0, duration: 0.45, stagger: 0.09, ease: 'power2.out', delay: 0.38 }
  );

  gsap.fromTo('.how-step',
    { y: 14 },
    { opacity: 1, y: 0, duration: 0.4, stagger: 0.1, ease: 'power2.out', delay: 0.45 }
  );

  gsap.fromTo('.tech-item',
    { scale: 0.88 },
    { opacity: 1, scale: 1, duration: 0.3, stagger: 0.06, ease: 'back.out(1.4)', delay: 0.5 }
  );
}

/* ═══════════════════════════════════════════════════════════════
   UTILITIES
   ═══════════════════════════════════════════════════════════════ */
function formatBytes(bytes) {
  if (bytes < 1024)       return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function base64ToBytes(b64) {
  const binStr = atob(b64);
  const bytes  = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
  return bytes;
}

/* ═══════════════════════════════════════════════════════════════
   INIT
   ═══════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  initParticles();
  initDashboard();
  setStatus('info', 'Ready — All operations run locally in your browser');

  // Dropzone pulse animation
  const dz = document.getElementById('hide-dropzone');
  if (dz) {
    gsap.to(dz, {
      boxShadow: '0 0 18px rgba(79,142,247,0.12)',
      duration: 1.8,
      yoyo: true,
      repeat: -1,
      ease: 'sine.inOut'
    });
  }

  // Header entrance
  gsap.fromTo('#app-header',
    { y: -60, opacity: 0 },
    { y: 0, opacity: 1, duration: 0.5, ease: 'power2.out' }
  );
  gsap.fromTo('#app-nav',
    { y: -20, opacity: 0 },
    { y: 0, opacity: 1, duration: 0.4, ease: 'power2.out', delay: 0.15 }
  );

  // ── Auto-set ngrok URL if server.py provided one ──
  updateSharePublicLink();
  renderShareQueue();
  renderInbox();
  shareCheckHealth(false);

  // Wire up extract password
  document.getElementById('extract-password').addEventListener('input', () => {
    checkExtractReady();
    advanceStepper('extract', 2);
  });

  // Wire up hide password live check
  document.getElementById('hide-password').addEventListener('input', () => {
    updatePasswordStrength('hide');
  });

  // Wire up hide text live req update
  document.getElementById('hide-secret-text').addEventListener('input', () => {
    updateRequiredBytes();
    if (document.getElementById('hide-secret-text').value.trim().length > 0) {
      advanceStepper('hide', 2);
    }
    checkHideReady();
  });
});

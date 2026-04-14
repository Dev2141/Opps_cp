const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const MAGIC = new Uint8Array([0x53, 0x54, 0x47, 0x31]); // STG1
const SALT = textEncoder.encode("STEG_SALT_2025");
const IV_LEN = 12;
const PBKDF_ITER = 65536;

const state = {
  carrierImage: null,
  stegoBlob: null,
  stegoDataUrl: "",
  selectedSecretFile: null,
  decodeImageData: null,
  analyzeImageData: null,
  inboxMessages: []
};

bindNavigation();
bindEvents();
updateModeUI();
updateCapacityStats();
updateHideWizard();
updateExtractWizard();
updateAnalyzeState();

function bindNavigation() {
  const views = ["dashboardView", "hideView", "extractView", "shareView", "analyzeView"];
  const show = (id) => {
    views.forEach((viewId) => {
      const el = document.getElementById(viewId);
      if (!el) return;
      el.classList.toggle("active", viewId === id);
    });
  };

  document.querySelectorAll(".action-card").forEach((card) => {
    card.addEventListener("click", () => show(card.dataset.target));
  });
  document.querySelectorAll("[data-open]").forEach((btn) => {
    btn.addEventListener("click", () => show(btn.dataset.open));
  });

  document.getElementById("homeBtn").addEventListener("click", () => show("dashboardView"));
  document.getElementById("openShareBtn").addEventListener("click", () => show("shareView"));
}

function setStatus(message, kind = "info") {
  const dot = document.getElementById("statusDot");
  const text = document.getElementById("statusText");
  const map = { info: "#3b82f6", success: "#22c55e", warn: "#f59e0b", error: "#ef4444" };
  const color = map[kind] || map.info;
  dot.style.background = color;
  dot.style.boxShadow = `0 0 0 4px ${hexToRgba(color, 0.22)}`;
  text.textContent = message;
}

window.addEventListener("error", (event) => {
  setStatus(`Runtime error: ${event.message}`, "error");
});

function hexToRgba(hex, alpha) {
  const c = hex.replace("#", "");
  const r = parseInt(c.slice(0, 2), 16);
  const g = parseInt(c.slice(2, 4), 16);
  const b = parseInt(c.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function getPayloadMode() {
  return document.querySelector('input[name="payloadMode"]:checked').value;
}

function updateModeUI() {
  const mode = getPayloadMode();
  document.getElementById("textWrap").classList.toggle("hidden", mode !== "text");
  document.getElementById("fileWrap").classList.toggle("hidden", mode !== "file");
  updateCapacityStats();
  updateHideWizard();
}

function estimateRequiredBytes() {
  const mode = getPayloadMode();
  let envelopeLen = 0;
  if (mode === "text") {
    const textBytes = textEncoder.encode(document.getElementById("secretText").value || "");
    envelopeLen = 4 + 1 + 2 + 2 + 8 + "text/plain".length + textBytes.length;
  } else if (state.selectedSecretFile) {
    const f = state.selectedSecretFile;
    envelopeLen = 4 + 1 + 2 + 2 + 8
      + textEncoder.encode(f.name || "hidden.bin").length
      + textEncoder.encode(f.type || "application/octet-stream").length
      + f.size;
  }
  return envelopeLen + 16 + IV_LEN + 4;
}

function updateCapacityStats() {
  const imageChip = document.getElementById("chipImage");
  const capChip = document.getElementById("chipCapacity");
  const reqChip = document.getElementById("chipRequired");

  if (!state.carrierImage) {
    imageChip.textContent = "Not loaded";
    capChip.textContent = "0 B";
    reqChip.textContent = "0 B";
    return;
  }

  const cap = Math.floor(state.carrierImage.width * state.carrierImage.height * 3 / 8);
  imageChip.textContent = `${state.carrierImage.width}x${state.carrierImage.height}`;
  capChip.textContent = formatBytes(cap);
  reqChip.textContent = formatBytes(estimateRequiredBytes());
}

function scorePassword(pw) {
  let score = 0;
  if (!pw) return 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return Math.min(score, 5);
}

function updateEncodeStrength() {
  const pw = document.getElementById("encodePassword").value || "";
  const score = scorePassword(pw);
  const pct = (score / 5) * 100;
  const bar = document.getElementById("encodeStrengthBar");
  const text = document.getElementById("encodeStrengthText");
  bar.style.width = `${pct}%`;
  text.textContent = `Password strength: ${score <= 1 ? "weak" : score <= 3 ? "medium" : "strong"}`;
}

function setStepper(stepperId, activeStep, doneUntil) {
  const items = document.querySelectorAll(`#${stepperId} li`);
  items.forEach((li) => {
    const s = Number(li.dataset.step || "0");
    li.classList.toggle("active", s === activeStep);
    li.classList.toggle("done", s <= doneUntil);
  });
}

function updateHideWizard() {
  const step1 = !!state.carrierImage;
  const mode = getPayloadMode();
  const step2 = mode === "text"
    ? !!(document.getElementById("secretText").value || "").trim()
    : !!state.selectedSecretFile;
  const step3 = !!(document.getElementById("encodePassword").value || "");
  const canEmbed = step1 && step2 && step3;
  document.getElementById("embedBtn").disabled = !canEmbed;

  const doneUntil = step1 ? (step2 ? (step3 ? 3 : 2) : 1) : 0;
  const active = !step1 ? 1 : !step2 ? 2 : !step3 ? 3 : 4;
  setStepper("hideStepper", active, doneUntil);
}

function updateExtractWizard() {
  const step1 = !!state.decodeImageData;
  const step2 = !!(document.getElementById("decodePassword").value || "");
  document.getElementById("extractBtn").disabled = !(step1 && step2);
  const doneUntil = step1 ? (step2 ? 2 : 1) : 0;
  const active = !step1 ? 1 : !step2 ? 2 : 3;
  setStepper("extractStepper", active, doneUntil);
}

function updateAnalyzeState() {
  document.getElementById("analyzeBtn").disabled = !state.analyzeImageData;
}

function setLoading(id, on) {
  document.getElementById(id).classList.toggle("hidden", !on);
}

function readFileAsDataURL(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(new Error("File read failed."));
    r.readAsDataURL(file);
  });
}

function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(new Error("File read failed."));
    r.readAsArrayBuffer(file);
  });
}

function loadImageFromUrl(url) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("Image load failed."));
    img.src = url;
  });
}

async function imageDataFromFile(file) {
  const dataUrl = await readFileAsDataURL(file);
  const img = await loadImageFromUrl(dataUrl);
  return drawImageToData(img);
}

async function imageDataFromBase64(base64) {
  const dataUrl = `data:image/png;base64,${base64}`;
  const img = await loadImageFromUrl(dataUrl);
  return drawImageToData(img);
}

function drawImageToData(img) {
  const canvas = document.getElementById("workCanvas");
  canvas.width = img.width;
  canvas.height = img.height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(img, 0, 0);
  return ctx.getImageData(0, 0, canvas.width, canvas.height);
}

function canvasToBlob(canvas) {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => blob ? resolve(blob) : reject(new Error("PNG export failed.")), "image/png");
  });
}

function downloadBlob(blob, fileName) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = fileName;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 500);
}

function buildEnvelope(type, fileName, mimeType, dataBytes) {
  const nameBytes = textEncoder.encode(fileName || "");
  const mimeBytes = textEncoder.encode(mimeType || "application/octet-stream");
  if (dataBytes.length > 0xffffffff) throw new Error("Payload too large.");
  const total = 4 + 1 + 2 + 2 + 8 + nameBytes.length + mimeBytes.length + dataBytes.length;
  const out = new Uint8Array(total);
  let p = 0;
  out.set(MAGIC, p); p += 4;
  out[p++] = type & 0xff;
  out[p++] = (nameBytes.length >> 8) & 0xff;
  out[p++] = nameBytes.length & 0xff;
  out[p++] = (mimeBytes.length >> 8) & 0xff;
  out[p++] = mimeBytes.length & 0xff;
  out[p++] = 0; out[p++] = 0; out[p++] = 0; out[p++] = 0;
  out[p++] = (dataBytes.length >>> 24) & 0xff;
  out[p++] = (dataBytes.length >>> 16) & 0xff;
  out[p++] = (dataBytes.length >>> 8) & 0xff;
  out[p++] = dataBytes.length & 0xff;
  out.set(nameBytes, p); p += nameBytes.length;
  out.set(mimeBytes, p); p += mimeBytes.length;
  out.set(dataBytes, p);
  return out;
}

function looksLikeEnvelope(bytes) {
  return bytes.length >= 4 && bytes[0] === MAGIC[0] && bytes[1] === MAGIC[1] && bytes[2] === MAGIC[2] && bytes[3] === MAGIC[3];
}

function parseEnvelope(bytes) {
  if (bytes.length < 17 || !looksLikeEnvelope(bytes)) throw new Error("Invalid envelope.");
  let p = 4;
  const type = bytes[p++];
  const nameLen = (bytes[p++] << 8) | bytes[p++];
  const mimeLen = (bytes[p++] << 8) | bytes[p++];
  const hi = ((bytes[p++] << 24) >>> 0) | (bytes[p++] << 16) | (bytes[p++] << 8) | bytes[p++];
  const lo = ((bytes[p++] << 24) >>> 0) | (bytes[p++] << 16) | (bytes[p++] << 8) | bytes[p++];
  if (hi !== 0) throw new Error("Payload too large for browser parser.");
  const len = lo >>> 0;
  if (p + nameLen + mimeLen + len > bytes.length) throw new Error("Truncated payload.");
  const fileName = textDecoder.decode(bytes.slice(p, p + nameLen)) || "hidden.bin"; p += nameLen;
  const mimeType = textDecoder.decode(bytes.slice(p, p + mimeLen)) || "application/octet-stream"; p += mimeLen;
  const data = bytes.slice(p, p + len);
  if (type !== 0 && type !== 1) throw new Error("Unsupported payload type.");
  return { isFile: type === 1, fileName, mimeType, data };
}

async function deriveKey(password) {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error("Web Crypto is unavailable in this browser/context.");
  }
  const keyMaterial = await crypto.subtle.importKey("raw", textEncoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: SALT, iterations: PBKDF_ITER, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function aesEncrypt(password, plain) {
  const key = await deriveKey(password);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, plain);
  const out = new Uint8Array(IV_LEN + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), IV_LEN);
  return out;
}

async function aesDecrypt(password, data) {
  if (data.length <= IV_LEN) throw new Error("Cipher payload too short.");
  const key = await deriveKey(password);
  const iv = data.slice(0, IV_LEN);
  const ct = data.slice(IV_LEN);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, ct);
  return new Uint8Array(plain);
}

function lsbEmbed(imageData, payload) {
  const full = new Uint8Array(4 + payload.length);
  full[0] = (payload.length >>> 24) & 0xff;
  full[1] = (payload.length >>> 16) & 0xff;
  full[2] = (payload.length >>> 8) & 0xff;
  full[3] = payload.length & 0xff;
  full.set(payload, 4);
  const data = imageData.data;
  let bitIdx = 0;
  const totalBits = full.length * 8;
  for (let i = 0; i < data.length && bitIdx < totalBits; i += 4) {
    for (let c = 0; c < 3 && bitIdx < totalBits; c++) {
      const b = (full[(bitIdx / 8) | 0] >> (7 - (bitIdx % 8))) & 1;
      data[i + c] = (data[i + c] & 0xfe) | b;
      bitIdx++;
    }
    data[i + 3] = 255;
  }
}

function lsbExtract(imageData) {
  const data = imageData.data;
  const maxBytes = Math.floor((data.length * 3) / (4 * 8));
  const raw = new Uint8Array(maxBytes);
  let bitIdx = 0;
  for (let i = 0; i < data.length && bitIdx < maxBytes * 8; i += 4) {
    for (let c = 0; c < 3 && bitIdx < maxBytes * 8; c++) {
      raw[(bitIdx / 8) | 0] |= (data[i + c] & 1) << (7 - (bitIdx % 8));
      bitIdx++;
    }
  }
  const len = ((raw[0] << 24) >>> 0) | (raw[1] << 16) | (raw[2] << 8) | raw[3];
  if (len <= 0 || len > raw.length - 4) throw new Error("No hidden data found (use stego PNG/BMP). ");
  return raw.slice(4, 4 + len);
}

function clearRecoveredFileLink() {
  const link = document.getElementById("decodedFileLink");
  link.classList.add("hidden");
  if (link.href) URL.revokeObjectURL(link.href);
  link.removeAttribute("href");
}

function setDecodeResult(text, kind = "info") {
  const el = document.getElementById("decodeResult");
  const pill = document.getElementById("decodeState");
  el.textContent = text;
  el.style.color = kind === "error" ? "#fecaca" : kind === "warn" ? "#fde68a" : "#e2e8f0";
  pill.textContent = kind === "success" ? "Extraction successful" : kind === "error" ? "Extraction failed" : "Awaiting input";
  pill.style.borderColor = kind === "success" ? "#22c55e" : kind === "error" ? "#ef4444" : "#334155";
}

function isLosslessStegoDecodeType(file) {
  const type = (file.type || "").toLowerCase();
  if (type === "image/png" || type === "image/bmp" || type === "image/x-ms-bmp") return true;
  const name = (file.name || "").toLowerCase();
  return name.endsWith(".png") || name.endsWith(".bmp");
}

async function handleEmbed() {
  setLoading("embedLoading", true);
  document.getElementById("embedSuccess").classList.add("hidden");
  try {
    if (!state.carrierImage) return setStatus("Upload an image first.", "warn");
    const pw = document.getElementById("encodePassword").value;
    if (!pw) return setStatus("Password is required.", "warn");

    let envelope;
    if (getPayloadMode() === "text") {
      const text = (document.getElementById("secretText").value || "").trim();
      if (!text) return setStatus("Secret text cannot be empty.", "warn");
      envelope = buildEnvelope(0, "", "text/plain", textEncoder.encode(text));
    } else {
      if (!state.selectedSecretFile) return setStatus("Choose a file to hide.", "warn");
      const bytes = new Uint8Array(await readFileAsArrayBuffer(state.selectedSecretFile));
      envelope = buildEnvelope(
        1,
        state.selectedSecretFile.name || "hidden.bin",
        state.selectedSecretFile.type || "application/octet-stream",
        bytes
      );
    }

    const cipher = await aesEncrypt(pw, envelope);
    const capBytes = Math.floor(state.carrierImage.width * state.carrierImage.height * 3 / 8);
    const needed = cipher.length + 4;
    if (needed > capBytes) throw new Error(`Carrier too small. Need ${formatBytes(needed)}, capacity ${formatBytes(capBytes)}.`);

    const canvas = document.getElementById("workCanvas");
    canvas.width = state.carrierImage.width;
    canvas.height = state.carrierImage.height;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    ctx.drawImage(state.carrierImage, 0, 0);
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    lsbEmbed(imgData, cipher);
    ctx.putImageData(imgData, 0, 0);

    state.stegoBlob = await canvasToBlob(canvas);
    state.stegoDataUrl = await readFileAsDataURL(state.stegoBlob);

    document.getElementById("saveStegoBtn").classList.remove("hidden");
    document.getElementById("embedSuccess").classList.remove("hidden");

    try {
      const b64 = state.stegoDataUrl.split(",")[1] || "";
      if (b64) {
        state.decodeImageData = await imageDataFromBase64(b64);
        document.getElementById("decodeImageNote").textContent = "Latest stego output loaded";
        setDecodeResult("Stego image loaded. Enter password and extract.", "info");
        updateExtractWizard();
      }
    } catch {
      // Ignore decode preload errors
    }

    setStatus("Message successfully hidden.", "success");
  } catch (err) {
    setStatus(`Hide failed: ${err.message}`, "error");
  } finally {
    setLoading("embedLoading", false);
  }
}

async function handleExtract() {
  setLoading("extractLoading", true);
  clearRecoveredFileLink();
  document.getElementById("copyResultBtn").classList.add("hidden");
  try {
    if (!state.decodeImageData) return setDecodeResult("Upload stego image first.", "warn");
    const pw = document.getElementById("decodePassword").value;
    if (!pw) return setDecodeResult("Enter decryption password.", "warn");

    const cipher = lsbExtract(state.decodeImageData);
    const plain = await aesDecrypt(pw, cipher);

    if (looksLikeEnvelope(plain)) {
      const payload = parseEnvelope(plain);
      if (payload.isFile) {
        const blob = new Blob([payload.data], { type: payload.mimeType || "application/octet-stream" });
        const link = document.getElementById("decodedFileLink");
        link.href = URL.createObjectURL(blob);
        link.download = payload.fileName || "recovered.bin";
        link.textContent = `Download ${payload.fileName || "recovered file"}`;
        link.classList.remove("hidden");
        setDecodeResult(`Recovered file: ${payload.fileName}\nType: ${payload.mimeType}\nSize: ${formatBytes(payload.data.length)}`, "success");
      } else {
        setDecodeResult(textDecoder.decode(payload.data) || "(empty text payload)", "success");
        document.getElementById("copyResultBtn").classList.remove("hidden");
      }
    } else {
      setDecodeResult(textDecoder.decode(plain), "success");
      document.getElementById("copyResultBtn").classList.remove("hidden");
    }

    setStatus("Extraction successful.", "success");
  } catch (err) {
    setDecodeResult(`Decode failed: ${err.message}`, "error");
    setStatus(`Decode failed: ${err.message}`, "error");
  } finally {
    setLoading("extractLoading", false);
  }
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

function analyzeStego(imageData) {
  const data = imageData.data;
  const freq = [new Array(256).fill(0), new Array(256).fill(0), new Array(256).fill(0)];
  const ones = [0, 0, 0];
  const bits = [0, 0, 0];
  let prev = -1, transitions = 0, compared = 0;
  for (let i = 0; i < data.length; i += 4) {
    const ch = [data[i], data[i + 1], data[i + 2]];
    for (let c = 0; c < 3; c++) {
      const v = ch[c];
      freq[c][v]++;
      const bit = v & 1;
      ones[c] += bit;
      bits[c]++;
      if (prev !== -1) {
        if (prev !== bit) transitions++;
        compared++;
      }
      prev = bit;
    }
  }
  const ratio = ones.map((v, i) => v / bits[i]);
  const chi = freq.map((f) => normalizedChi(f));
  const totalBits = bits[0] + bits[1] + bits[2];
  const totalOnes = ones[0] + ones[1] + ones[2];
  const entropy = binaryEntropy(totalOnes / totalBits);
  const transition = compared > 0 ? transitions / compared : 0;
  const avgRatio = (ratio[0] + ratio[1] + ratio[2]) / 3;
  const maxPayload = Math.floor((data.length * 3) / (4 * 8)) - 4;
  const headerLength = readStegoLengthHeader(imageData);
  const headerPlausible = headerLength >= 40 && headerLength <= maxPayload;
  let headerIndicator = headerPlausible ? 1 : 0;
  if (headerPlausible) {
    const sizeRatio = maxPayload > 0 ? headerLength / maxPayload : 0;
    if (sizeRatio > 0.98) headerIndicator *= 0.8;
    if (headerLength < 56) headerIndicator *= 0.85;
  }

  const chiIndicator = (chi[0] + chi[1] + chi[2]) / 3;
  const balanceIndicator = clamp01(1 - Math.abs(avgRatio - 0.5) * 2);
  const entropyIndicator = clamp01(entropy);
  const transitionIndicator = clamp01(1 - Math.abs(transition - 0.5) * 2);

  const confidence = clamp01(
    0.18 * chiIndicator + 0.07 * balanceIndicator + 0.05 * entropyIndicator + 0.05 * transitionIndicator + 0.65 * headerIndicator
  ) * 100;

  const verdict = confidence >= 72 ? "Likely hidden data" : confidence >= 45 ? "Suspicious" : "Likely clean";
  return { ratio, chi, entropy, transition, confidence, verdict, headerLength, headerPlausible };
}

function readStegoLengthHeader(imageData) {
  const data = imageData.data;
  let len = 0;
  let bitCount = 0;
  for (let i = 0; i < data.length && bitCount < 32; i += 4) {
    for (let c = 0; c < 3 && bitCount < 32; c++) {
      len = ((len << 1) | (data[i + c] & 1)) >>> 0;
      bitCount++;
    }
  }
  return len >>> 0;
}

function normalizedChi(freq) {
  let chi = 0;
  let total = 0;
  for (let i = 0; i < 256; i += 2) {
    const a = freq[i], b = freq[i + 1];
    const sum = a + b;
    total += sum;
    if (sum > 0) {
      const d = a - b;
      chi += (d * d) / sum;
    }
  }
  if (total === 0) return 0;
  return clamp01(1 - Math.exp(-6 * (chi / total)));
}

function binaryEntropy(p1) {
  const p0 = 1 - p1;
  return entropyTerm(p0) + entropyTerm(p1);
}

function entropyTerm(p) {
  if (p <= 0) return 0;
  return -p * Math.log2(p);
}

function clamp01(v) {
  return Math.max(0, Math.min(1, v));
}

function getMailboxCreds() {
  return {
    mailboxId: (document.getElementById("mailboxId").value || "").trim(),
    passphrase: document.getElementById("mailboxPassphrase").value || ""
  };
}

async function apiPost(path, body) {
  const base = document.getElementById("serverUrl").value.trim().replace(/\/+$/, "");
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  let json;
  try {
    json = await res.json();
  } catch {
    throw new Error(`HTTP ${res.status}`);
  }
  if (!res.ok || json.ok === false) throw new Error(json.error || `HTTP ${res.status}`);
  return json;
}

async function handleRegisterMailbox() {
  try {
    const creds = getMailboxCreds();
    if (!creds.mailboxId || !creds.passphrase) return setStatus("Mailbox ID and passphrase are required.", "warn");
    const res = await apiPost("/api/mailbox/register", creds);
    setStatus(res.ok ? `Mailbox \"${creds.mailboxId}\" ready.` : (res.message || "Mailbox exists."), res.ok ? "success" : "warn");
  } catch (err) {
    setStatus(`Mailbox register failed: ${err.message}`, "error");
  }
}

async function handleSendStego() {
  try {
    if (!state.stegoDataUrl) return setStatus("Generate stego image first.", "warn");
    const creds = getMailboxCreds();
    if (!creds.mailboxId || !creds.passphrase) return setStatus("Mailbox ID and passphrase are required.", "warn");
    const sender = (document.getElementById("senderName").value || "").trim() || "anonymous";
    const b64 = state.stegoDataUrl.split(",")[1] || state.stegoDataUrl;
    const res = await apiPost("/api/message/send", {
      mailboxId: creds.mailboxId,
      passphrase: creds.passphrase,
      sender,
      stegoImageBase64: b64
    });
    setStatus(`Sent. Message ID: ${res.messageId}`, "success");
    await handleRefreshInbox();
  } catch (err) {
    setStatus(`Send failed: ${err.message}`, "error");
  }
}

function formatTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
}

function renderInbox(messages) {
  const body = document.getElementById("inboxBody");
  body.innerHTML = "";
  if (!messages.length) {
    const empty = document.createElement("div");
    empty.className = "empty-row";
    empty.textContent = "No messages in mailbox";
    body.appendChild(empty);
    return;
  }

  for (const m of messages) {
    const row = document.createElement("div");
    row.className = "inbox-row";

    const meta = document.createElement("div");
    meta.className = "inbox-meta";

    const sender = document.createElement("span");
    sender.textContent = `Sender: ${m.sender || "unknown"}`;
    const time = document.createElement("span");
    time.textContent = `Time: ${formatTime(m.timestamp)}`;
    const size = document.createElement("span");
    size.textContent = `Size: ${formatBytes(Number(m.sizeBytes || 0))}`;

    meta.appendChild(sender);
    meta.appendChild(time);
    meta.appendChild(size);

    const actions = document.createElement("div");
    actions.className = "inbox-actions";

    const dl = document.createElement("button");
    dl.type = "button";
    dl.className = "ghost-btn";
    dl.textContent = "Download";
    dl.dataset.action = "download";
    dl.dataset.id = m.messageId;

    const del = document.createElement("button");
    del.type = "button";
    del.className = "ghost-btn";
    del.textContent = "Delete";
    del.dataset.action = "delete";
    del.dataset.id = m.messageId;

    actions.appendChild(dl);
    actions.appendChild(del);

    row.appendChild(meta);
    row.appendChild(actions);
    body.appendChild(row);
  }
}

async function handleRefreshInbox() {
  try {
    const creds = getMailboxCreds();
    if (!creds.mailboxId || !creds.passphrase) return setStatus("Mailbox ID and passphrase are required.", "warn");
    const res = await apiPost("/api/message/list", creds);
    state.inboxMessages = res.messages || [];
    renderInbox(state.inboxMessages);
    setStatus(`Inbox loaded: ${state.inboxMessages.length} message(s).`, "success");
  } catch (err) {
    setStatus(`Inbox refresh failed: ${err.message}`, "error");
  }
}

async function handleDownloadMessage(messageId) {
  try {
    if (!messageId) return setStatus("Missing message ID.", "warn");
    const creds = getMailboxCreds();
    if (!creds.mailboxId || !creds.passphrase) return setStatus("Mailbox ID and passphrase are required.", "warn");
    const res = await apiPost("/api/message/download", {
      mailboxId: creds.mailboxId,
      passphrase: creds.passphrase,
      messageId
    });
    const bytes = base64ToBytes(res.imageBase64);
    downloadBlob(new Blob([bytes], { type: "image/png" }), `received_${res.messageId}.png`);
    state.decodeImageData = await imageDataFromBase64(res.imageBase64);
    document.getElementById("decodeImageNote").textContent = `Loaded from inbox: received_${res.messageId}.png`;
    updateExtractWizard();
    setStatus(`Downloaded and loaded ${res.messageId} for extract.`, "success");
  } catch (err) {
    setStatus(`Download failed: ${err.message}`, "error");
  }
}

async function handleDeleteMessage(messageId) {
  try {
    if (!messageId) return setStatus("Missing message ID.", "warn");
    const creds = getMailboxCreds();
    if (!creds.mailboxId || !creds.passphrase) return setStatus("Mailbox ID and passphrase are required.", "warn");
    await apiPost("/api/message/delete", {
      mailboxId: creds.mailboxId,
      passphrase: creds.passphrase,
      messageId
    });
    await handleRefreshInbox();
    setStatus("Message deleted.", "success");
  } catch (err) {
    setStatus(`Delete failed: ${err.message}`, "error");
  }
}

function handleAnalyze() {
  setLoading("analyzeLoading", true);
  try {
    if (!state.analyzeImageData) return setStatus("Choose an image for analysis first.", "warn");
    const r = analyzeStego(state.analyzeImageData);
    document.getElementById("metricVerdict").textContent = r.verdict;
    document.getElementById("metricConfidence").textContent = `${r.confidence.toFixed(2)}%`;
    document.getElementById("metricLsb").textContent = `${r.ratio[0].toFixed(3)} / ${r.ratio[1].toFixed(3)} / ${r.ratio[2].toFixed(3)}`;
    document.getElementById("metricChi").textContent = `${r.chi[0].toFixed(3)} / ${r.chi[1].toFixed(3)} / ${r.chi[2].toFixed(3)}`;
    document.getElementById("metricEntropy").textContent = r.entropy.toFixed(4);
    document.getElementById("metricTransition").textContent = `${r.transition.toFixed(4)} | hdr=${r.headerLength} (${r.headerPlausible ? "ok" : "no"})`;
    document.getElementById("confidenceBar").style.width = `${r.confidence.toFixed(2)}%`;

    const verdict = document.getElementById("verdictCard");
    verdict.classList.remove("good", "warn", "bad");
    verdict.classList.add(r.confidence >= 72 ? "bad" : r.confidence >= 45 ? "warn" : "good");

    setStatus(`Analysis complete: ${r.verdict} (${r.confidence.toFixed(1)}%).`, "success");
  } catch (err) {
    setStatus(`Analyze failed: ${err.message}`, "error");
  } finally {
    setLoading("analyzeLoading", false);
  }
}

async function loadCarrier(file) {
  const dataUrl = await readFileAsDataURL(file);
  const img = await loadImageFromUrl(dataUrl);
  state.carrierImage = img;
  state.stegoBlob = null;
  state.stegoDataUrl = "";
  document.getElementById("saveStegoBtn").classList.add("hidden");
  const preview = document.getElementById("carrierPreview");
  preview.src = dataUrl;
  preview.classList.remove("hidden");
  updateCapacityStats();
  updateHideWizard();
  setStatus(`Carrier loaded: ${file.name}`, "success");
}

function togglePassword(inputId, btnId) {
  const input = document.getElementById(inputId);
  const btn = document.getElementById(btnId);
  const isHidden = input.type === "password";
  input.type = isHidden ? "text" : "password";
  btn.textContent = isHidden ? "Hide" : "Show";
}

function bindEvents() {
  document.querySelectorAll('input[name="payloadMode"]').forEach((radio) => radio.addEventListener("change", updateModeUI));
  document.getElementById("secretText").addEventListener("input", () => {
    updateCapacityStats();
    updateHideWizard();
  });

  const carrierDrop = document.getElementById("carrierDrop");
  const carrierFile = document.getElementById("carrierFile");
  carrierDrop.addEventListener("click", () => carrierFile.click());
  carrierDrop.addEventListener("dragover", (e) => {
    e.preventDefault();
    carrierDrop.classList.add("dragover");
  });
  carrierDrop.addEventListener("dragleave", () => carrierDrop.classList.remove("dragover"));
  carrierDrop.addEventListener("drop", async (e) => {
    e.preventDefault();
    carrierDrop.classList.remove("dragover");
    const f = e.dataTransfer.files[0];
    if (f) await loadCarrier(f);
  });
  carrierFile.addEventListener("change", async (e) => {
    const f = e.target.files[0];
    if (f) await loadCarrier(f);
  });

  document.getElementById("pickSecretFileBtn").addEventListener("click", () => document.getElementById("secretFile").click());
  document.getElementById("secretFile").addEventListener("change", (e) => {
    state.selectedSecretFile = e.target.files[0] || null;
    document.getElementById("secretFileNote").textContent = state.selectedSecretFile
      ? `${state.selectedSecretFile.name} (${formatBytes(state.selectedSecretFile.size)})`
      : "No file selected";
    updateCapacityStats();
    updateHideWizard();
  });

  document.getElementById("encodePassword").addEventListener("input", () => {
    updateEncodeStrength();
    updateHideWizard();
  });
  document.getElementById("toggleEncodePassword").addEventListener("click", () => togglePassword("encodePassword", "toggleEncodePassword"));
  document.getElementById("embedBtn").addEventListener("click", handleEmbed);
  document.getElementById("saveStegoBtn").addEventListener("click", () => {
    if (!state.stegoBlob) return setStatus("No stego image to save.", "warn");
    downloadBlob(state.stegoBlob, "stego_output.png");
    setStatus("Stego image downloaded.", "success");
  });

  document.getElementById("pickDecodeImageBtn").addEventListener("click", () => document.getElementById("decodeImageFile").click());
  document.getElementById("decodeImageFile").addEventListener("change", async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    if (!isLosslessStegoDecodeType(f)) {
      state.decodeImageData = null;
      document.getElementById("decodeImageNote").textContent = `${f.name} (${formatBytes(f.size)})`;
      setDecodeResult("Use PNG/BMP stego output (JPEG is lossy and breaks hidden bits).", "warn");
      setStatus("Extraction requires PNG/BMP stego image.", "warn");
      updateExtractWizard();
      return;
    }
    state.decodeImageData = await imageDataFromFile(f);
    document.getElementById("decodeImageNote").textContent = `${f.name} (${formatBytes(f.size)})`;
    setDecodeResult("Stego image loaded. Enter password and extract.", "info");
    updateExtractWizard();
  });
  document.getElementById("decodePassword").addEventListener("input", updateExtractWizard);
  document.getElementById("toggleDecodePassword").addEventListener("click", () => togglePassword("decodePassword", "toggleDecodePassword"));
  document.getElementById("extractBtn").addEventListener("click", handleExtract);
  document.getElementById("copyResultBtn").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(document.getElementById("decodeResult").textContent || "");
      setStatus("Extracted text copied.", "success");
    } catch {
      setStatus("Copy failed in this browser context.", "warn");
    }
  });

  document.getElementById("registerMailboxBtn").addEventListener("click", handleRegisterMailbox);
  document.getElementById("sendStegoBtn").addEventListener("click", handleSendStego);
  document.getElementById("refreshInboxBtn").addEventListener("click", handleRefreshInbox);
  document.getElementById("inboxBody").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-action]");
    if (!btn) return;
    const id = btn.dataset.id || "";
    if (btn.dataset.action === "download") {
      handleDownloadMessage(id);
    } else if (btn.dataset.action === "delete") {
      handleDeleteMessage(id);
    }
  });

  document.getElementById("pickAnalyzeImageBtn").addEventListener("click", () => document.getElementById("analyzeImageFile").click());
  document.getElementById("analyzeImageFile").addEventListener("change", async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    state.analyzeImageData = await imageDataFromFile(f);
    document.getElementById("analyzeImageNote").textContent = `${f.name} (${formatBytes(f.size)})`;
    updateAnalyzeState();
  });
  document.getElementById("analyzeBtn").addEventListener("click", handleAnalyze);
}

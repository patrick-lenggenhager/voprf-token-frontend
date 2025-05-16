import { secp256k1 } from 'https://cdn.jsdelivr.net/npm/@noble/curves@1.9.1/secp256k1.js/+esm';
import { sha256 } from 'https://cdn.jsdelivr.net/npm/@noble/hashes@1.8.0/sha2.js/+esm';
import { bytesToHex } from 'https://cdn.jsdelivr.net/npm/@noble/hashes@1.8.0/utils.js/+esm';

const { utils, CURVE, ProjectivePoint } = secp256k1;

const msgEl = document.getElementById('message');
const tokenEl = document.getElementById('token');
const formEl = document.getElementById('form-link');
const formUrlEl = document.getElementById('form-url');
const copyTokenBtn = document.getElementById('copy-token');
const copyUrlBtn = document.getElementById('copy-url');

function getQueryParam(name) {
  return new URLSearchParams(window.location.search).get(name);
}

function modInverse(a, n) {
  let t = 0n, newT = 1n;
  let r = n, newR = a;
  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  if (r > 1n) throw new Error('Not invertible');
  return t < 0n ? t + n : t;
}

function base64urlEncode(buf) {
  return btoa(String.fromCharCode(...buf))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function setLink(url) {
  formEl.href = url;
  formUrlEl.textContent = url;
}

async function main() {
  const backendURL = 'https://voprf-token-backend.onrender.com/voprf/evaluate';
  //const backendURL = 'http://localhost:3000/voprf/evaluate';
  const accessToken = getQueryParam('token');
  const encodedFormURL = getQueryParam('form');
  const tokenSection = document.getElementById('token-section');
  const countdownEl = document.getElementById('countdown');

  tokenSection.style.display = 'none'; // always hidden initially

  if (!accessToken || !encodedFormURL) {
    msgEl.textContent = '❌ Missing token or form parameter in URL.';
    return;
  }

  const formURLPrefix = decodeURIComponent(encodedFormURL);
  let finalURL = `${formURLPrefix}=`;
  setLink(finalURL);

  let seconds = 60;
  const countdownInterval = setInterval(() => {
    seconds--;
    countdownEl.textContent = seconds;

    if (seconds <= 0) {
      clearInterval(countdownInterval);
      msgEl.textContent = '⏳ Server is taking too long to respond. Please wait.';
    }
  }, 1000);

  try {
    const xBytes = utils.randomPrivateKey();
    const h = BigInt('0x' + bytesToHex(sha256(xBytes))) % CURVE.n;
    const H = ProjectivePoint.BASE.multiply(h);

    const rBytes = utils.randomPrivateKey();
    const r = BigInt('0x' + bytesToHex(rBytes));
    const blinded = H.multiply(r);

    const res = await fetch(backendURL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blinded: blinded.toHex(true), token: accessToken })
    });

    if (!res.ok) throw new Error((await res.json()).error || res.statusText);

    const { evaluated } = await res.json();
    const evaluatedPoint = ProjectivePoint.fromHex(evaluated);
    const rInv = modInverse(r, CURVE.n);
    const final = evaluatedPoint.multiply(rInv);

    const finalToken = new Uint8Array([...xBytes, ...final.toRawBytes(true)]);
    const tokenString = base64urlEncode(finalToken);

    clearInterval(countdownInterval);
    msgEl.textContent = '✅ Your anonymous token was generated successfully. You can now either copy it and later paste it into the form, or use the link below to open the form directly. You can also copy the link to the form to open it in a private browser window. If you wait, you will automatically be redirected to the form.';
    tokenEl.textContent = tokenString;
    tokenSection.style.display = 'block'; // show token section
    finalURL = `${formURLPrefix}=${encodeURIComponent(tokenString)}`;

  } catch (err) {
    console.warn("❌ Token generation failed, fallback to empty token:", err);
    clearInterval(countdownInterval);
    msgEl.textContent = `❌ Failed to verify access token: ${err.message} You can still access the form but must paste your token manually.`;
  }

  // Show link regardless of outcome
  setLink(finalURL);

  // Auto-open
  setTimeout(() => window.open(finalURL, '_blank'), 3000);
}

// Clipboard copy handlers
copyTokenBtn.onclick = () => {
  navigator.clipboard.writeText(tokenEl.textContent).then(() => {
    copyTokenBtn.textContent = "✅ Copied!";
    setTimeout(() => copyTokenBtn.textContent = "📋 Copy Token", 1500);
  });
};

copyUrlBtn.onclick = () => {
  navigator.clipboard.writeText(formUrlEl.textContent).then(() => {
    copyUrlBtn.textContent = "✅ Copied!";
    setTimeout(() => copyUrlBtn.textContent = "📋 Copy URL", 1500);
  });
};

main();

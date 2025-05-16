import { secp256k1 } from 'https://cdn.jsdelivr.net/npm/@noble/curves@1.9.1/secp256k1.js/+esm';
import { sha256 } from 'https://cdn.jsdelivr.net/npm/@noble/hashes@1.8.0/sha2.js/+esm';
import { bytesToHex } from 'https://cdn.jsdelivr.net/npm/@noble/hashes@1.8.0/utils.js/+esm';

const { utils, CURVE, ProjectivePoint } = secp256k1;
const msgEl = document.getElementById('message');
const tokenEl = document.getElementById('token');
const linkEl = document.getElementById('form-link');

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

async function main() {
  console.log("✅ script.js loaded and main() started");

  const backendURL = 'http://localhost:3000/voprf/evaluate';
  const accessToken = getQueryParam('token');
  const encodedFormURL = getQueryParam('form');

  if (!accessToken || !encodedFormURL) {
    msgEl.textContent = '❌ Missing token or form parameter in URL.';
    console.error("Missing token or form:", { accessToken, encodedFormURL });
    return;
  }

  console.log("✅ URL params:", { accessToken, encodedFormURL });

  const formURLPrefix = decodeURIComponent(encodedFormURL);

  try {
    // Step 1: Generate random scalar x (input)
    const xBytes = utils.randomPrivateKey();

    // Step 2: H = G^hash(x)
    const h = BigInt('0x' + bytesToHex(sha256(xBytes))) % CURVE.n;
    const H = ProjectivePoint.BASE.multiply(h);

    // Step 3: Blind
    const rBytes = utils.randomPrivateKey();
    const r = BigInt('0x' + bytesToHex(rBytes));
    const blinded = H.multiply(r);

    // Step 4: POST to backend
    const res = await fetch(backendURL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        blinded: blinded.toHex(true),
        token: accessToken
      })
    });

    if (!res.ok) {
      const { error } = await res.json().catch(() => ({}));
      msgEl.textContent = `❌ VOPRF failed: ${error || res.statusText}`;
      return;
    }

    const { evaluated } = await res.json();
    const evaluatedPoint = ProjectivePoint.fromHex(evaluated);

    // Step 5: Unblind
    const rInv = modInverse(r, CURVE.n);
    const final = evaluatedPoint.multiply(rInv);
    const finalToken = new Uint8Array([...xBytes, ...final.toRawBytes(true)]);
    const tokenString = base64urlEncode(finalToken);

    // Step 6: Construct full form link
    const fullFormURL = `${formURLPrefix}=${encodeURIComponent(tokenString)}`;

    // Step 7: Display result
    msgEl.textContent = '✅ Your anonymous token was generated successfully.';
    tokenEl.textContent = tokenString;
    linkEl.href = fullFormURL;
    linkEl.textContent = 'Submit anonymously via Google Form';

    // Step 8: Show warning
    const warning = document.createElement('p');
    warning.textContent = `⚠️ This access token has now been used. Please use the anonymous token above immediately, or store it safely. 
For enhanced privacy, consider opening the form link in a private browsing window.`;
    document.body.appendChild(warning);

    // Step 9: Auto-open after delay
    setTimeout(() => {
      window.open(fullFormURL, '_blank', 'noopener');
    }, 3000);

  } catch (err) {
    msgEl.textContent = `❌ Unexpected error: ${err.message}`;
  }
}

main();

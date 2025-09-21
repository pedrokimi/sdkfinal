;(function (global) {
  function collectFingerprint() {
    try {
      const nav = navigator || {};
      const lang = (nav.languages && nav.languages[0]) || nav.language || '';
      const ua = nav.userAgent || '';
      const screenInfo = {
        width: window.screen && window.screen.width,
        height: window.screen && window.screen.height,
        pixelRatio: window.devicePixelRatio
      };
      const timezoneOffset = new Date().getTimezoneOffset();
      return {
        language: lang,
        userAgent: ua,
        timezoneOffset,
        screen: screenInfo,
        sessionMeta: {
          referrer: document.referrer || '',
          url: location.href,
          visibility: document.visibilityState
        }
      };
    } catch (e) {
      return {};
    }
  }

  function loadScript(url) {
    return new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = url;
      s.onload = resolve;
      s.onerror = reject;
      document.head.appendChild(s);
    });
  }

  function joinUrl(base, path) {
    if (!path) return base || '';
    if (path.startsWith('http://') || path.startsWith('https://')) return path;
    const b = (base || '').endsWith('/') ? (base || '').slice(0, -1) : (base || '');
    const p = path.startsWith('/') ? path : `/${path}`;
    return `${b}${p}`;
  }

  function initIdentitySdk(options = {}) {
    const baseUrl = options.baseUrl || '';
    const endpoint = options.endpoint || '/identity/verify';
    const biometric = options.biometric || { enabled: false };

    async function verify(extraSignals) {
      const payload = collectFingerprint();
      if (extraSignals && typeof extraSignals === 'object') {
        Object.assign(payload, { extraSignals });
      }
      const url = joinUrl(baseUrl, endpoint);
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      return res.json();
    }

    async function initiateChallenge({ type, email, userLabel, referenceEmbedding }) {
      const url = joinUrl(baseUrl, '/identity/challenge/initiate');
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, email, userLabel, referenceEmbedding })
      })
      return res.json()
    }

    async function verifyChallenge({ type, challengeId, code, embedding }) {
      const url = joinUrl(baseUrl, '/identity/challenge/verify');
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, challengeId, code, embedding })
      })
      return res.json()
    }

    async function ensureBiometryModels(basePath) {
      if (!biometric.enabled) return false;
      if (!window.faceapi) {
        // Load TFJS and face-api UMD from CDN
        await loadScript('https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@4.19.0/dist/tf.min.js');
        await loadScript('https://cdn.jsdelivr.net/npm/face-api.js@0.22.2/dist/face-api.min.js');
      }
      const faceapi = window.faceapi;
      const models = basePath || 'https://justadudewhohacks.github.io/face-api.js/models'
      await Promise.all([
        faceapi.nets.tinyFaceDetector.loadFromUri(models),
        faceapi.nets.faceLandmark68Net.loadFromUri(models),
        faceapi.nets.faceRecognitionNet.loadFromUri(models)
      ]);
      return true;
    }

    async function captureFaceEmbedding(videoElement, options = {}) {
      if (!biometric.enabled) return null;
      const faceapi = window.faceapi;
      const detection = await faceapi.detectSingleFace(
        videoElement,
        new faceapi.TinyFaceDetectorOptions({ scoreThreshold: options.scoreThreshold || 0.5 })
      ).withFaceLandmarks().withFaceDescriptor();
      if (!detection) return null;
      return Array.from(detection.descriptor);
    }

    return { verify, initiateChallenge, verifyChallenge, ensureBiometryModels, captureFaceEmbedding };
  }

  global.IdentitySDK = { initIdentitySdk };
})(window);



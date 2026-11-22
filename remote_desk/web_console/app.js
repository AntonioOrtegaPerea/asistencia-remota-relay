/* Asistencia Remota Antonio Ortega — Consola PWA para iPhone (iOS) */
(function () {
  "use strict";

  const DEFAULT_PASSWORD = "AntonioOrtega@";
  const PEERS_KEY = "ao_remote_peers_v1";
  const DELETED_KEY = "ao_remote_deleted_v1";
  const RELAY_KEY = "ao_remote_relay_url_v1";

  // Tipos de mensaje binarios (idénticos a remote_desk/protocol.py)
  const MSG_HELLO = 0x01;
  const MSG_FRAME = 0x02;
  const MSG_FRAME_ACK = 0x03;
  const MSG_INPUT = 0x04;
  const MSG_SETTINGS = 0x05;
  const MSG_PING = 0x06;
  const MSG_PONG = 0x07;
  const MSG_CONTROL_STATUS = 0x08;
  const MSG_FILE_START = 0x10;
  const MSG_FILE_CHUNK = 0x11;
  const MSG_FILE_END = 0x12;
  const MSG_FILE_STATUS = 0x13;
  const FILE_CHUNK_SIZE = 64 * 1024;

  const QUALITY_PRESETS = {
    low: { quality: 45, scale: 0.65, fps: 14 },
    mid: { quality: 62, scale: 0.80, fps: 18 },
    high: { quality: 80, scale: 0.95, fps: 24 },
  };

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const $ = (id) => document.getElementById(id);

  // =========================================================================
  // Utilidades de protocolo y agenda local (localStorage)
  // =========================================================================
  function normalizeSessionId(raw) {
    const cleaned = (raw || "").trim().replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
    if (cleaned.length === 9 && /^\d+$/.test(cleaned)) {
      return `${cleaned.slice(0, 3)}-${cleaned.slice(3, 6)}-${cleaned.slice(6)}`;
    }
    return cleaned;
  }

  function defaultRelayUrl() {
    const saved = localStorage.getItem(RELAY_KEY);
    if (saved) return saved;
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${location.host}`;
  }

  function loadPeers() {
    try {
      const raw = JSON.parse(localStorage.getItem(PEERS_KEY) || "[]");
      if (!Array.isArray(raw)) return [];
      return raw.map((p) => ({
        ...p,
        mode: p.mode === "direct" ? "direct" : "relay",
        key: p.key || `${p.mode === "direct" ? "direct" : "relay"}:${normalizeSessionId(p.id || p.target || "")}`,
        updated_at: Number(p.updated_at || 0) || Date.now(),
      }));
    } catch {
      return [];
    }
  }

  function savePeers(list) {
    localStorage.setItem(PEERS_KEY, JSON.stringify(list));
  }

  function loadDeleted() {
    try {
      const raw = JSON.parse(localStorage.getItem(DELETED_KEY) || "{}");
      return raw && typeof raw === "object" ? raw : {};
    } catch {
      return {};
    }
  }

  function saveDeleted(obj) {
    localStorage.setItem(DELETED_KEY, JSON.stringify(obj));
  }

  function makePeerKey(mode, target) {
    const m = mode === "direct" ? "direct" : "relay";
    const t = m === "relay" ? normalizeSessionId(target) : String(target || "").trim().toLowerCase();
    return `${m}:${t}`;
  }

  function upsertPeer({ id, alias, hostname, relayUrl, password, remember }) {
    const normId = normalizeSessionId(id);
    const key = makePeerKey("relay", normId);
    const list = loadPeers();
    const deleted = loadDeleted();
    delete deleted[key];
    saveDeleted(deleted);

    const now = new Date().toISOString().slice(0, 16).replace("T", " ");
    const nowMs = Date.now();
    let rec = list.find((p) => p.id === normId || p.key === key);
    if (!rec) {
      rec = {
        key,
        mode: "relay",
        id: normId,
        alias: (alias || hostname || normId).trim(),
        hostname: hostname || "",
        relayUrl: relayUrl || defaultRelayUrl(),
        password: remember ? password : "",
        favorite: false,
        notes: "",
        lastConnected: now,
        updated_at: nowMs,
      };
      list.unshift(rec);
    } else {
      rec.key = key;
      if (alias && alias.trim()) rec.alias = alias.trim();
      else if (hostname && (!rec.alias || rec.alias === rec.id)) rec.alias = hostname;
      if (hostname) rec.hostname = hostname;
      if (relayUrl) rec.relayUrl = relayUrl;
      if (remember && password) rec.password = password;
      rec.lastConnected = now;
      rec.updated_at = nowMs;
    }
    savePeers(list);
    renderPeerList();
    triggerCloudSync();
  }

  // =========================================================================
  // Sincronización en la nube cifrada E2E (PC Windows <-> iPhone)
  // =========================================================================
  let cachedVaultKeys = null;
  let syncInProgress = false;
  let syncPending = false;
  let presenceInProgress = false;
  const peerPresence = {}; // { "915-520-915": "online" | "busy" | "offline" }

  async function refreshPresence() {
    if (presenceInProgress || connected) return;
    const peers = loadPeers();
    if (!peers.length) return;
    const byRelay = new Map();
    const defUrl = ($("inp-relay").value || "").trim() || defaultRelayUrl();
    for (const p of peers) {
      if (p.mode === "direct") continue;
      const url = (p.relayUrl || defUrl || "").trim();
      if (!/^wss?:\/\//i.test(url)) continue;
      if (!byRelay.has(url)) byRelay.set(url, []);
      byRelay.get(url).push(p.id);
    }
    if (!byRelay.size) return;

    presenceInProgress = true;
    try {
      await Promise.all(
        Array.from(byRelay.entries()).map(([url, ids]) =>
          new Promise((resolve) => {
            let done = false;
            const finish = () => { if (!done) { done = true; resolve(); } };
            const sock = new WebSocket(url);
            const timer = setTimeout(() => { try { sock.close(); } catch {} finish(); }, 12000);
            sock.onopen = () => {
              sock.send(JSON.stringify({ type: "check_presence", session_ids: ids }));
            };
            sock.onerror = () => { clearTimeout(timer); finish(); };
            sock.onclose = () => { clearTimeout(timer); finish(); };
            sock.onmessage = (ev) => {
              try {
                const msg = JSON.parse(ev.data);
                if (msg.type === "presence_status" && msg.statuses) {
                  for (const id of ids) {
                    peerPresence[id] = msg.statuses[id] || "offline";
                  }
                }
              } catch {}
              clearTimeout(timer);
              try { sock.close(); } catch {}
              finish();
            };
          })
        )
      );
      renderPeerList();
    } finally {
      presenceInProgress = false;
    }
  }

  function setSyncLabel(text, color) {
    const el = $("sync-status");
    if (!el) return;
    el.textContent = text;
    el.style.color = color || "var(--muted)";
  }

  function exportSyncPayload() {
    const peers = loadPeers().map((p) => ({
      key: p.key || makePeerKey(p.mode || "relay", p.id),
      mode: p.mode === "direct" ? "direct" : "relay",
      target: p.id,
      alias: p.alias || "",
      hostname: p.hostname || "",
      relay_url: p.relayUrl || defaultRelayUrl(),
      password: p.password || "",
      favorite: !!p.favorite,
      notes: p.notes || "",
      last_connected: p.lastConnected || "",
      connect_count: Number(p.connectCount || 1),
      updated_at: Number(p.updated_at || Date.now()),
    }));
    return { version: 1, peers, deleted: loadDeleted() };
  }

  function mergeSyncPayload(remote) {
    const localList = loadPeers();
    const localMap = new Map(localList.map((p) => [p.key || makePeerKey(p.mode || "relay", p.id), p]));
    const localDeleted = loadDeleted();
    const remoteDeleted = (remote && typeof remote.deleted === "object" && remote.deleted) ? remote.deleted : {};
    const remoteMap = new Map();

    for (const item of (remote && Array.isArray(remote.peers) ? remote.peers : [])) {
      if (!item || typeof item !== "object") continue;
      const mode = item.mode === "direct" ? "direct" : "relay";
      const target = String(item.target || item.id || "").trim();
      if (!target) continue;
      const cleanTarget = mode === "relay" ? normalizeSessionId(target) : target;
      const key = item.key || makePeerKey(mode, cleanTarget);
      remoteMap.set(key, {
        key,
        mode,
        id: cleanTarget,
        alias: String(item.alias || ""),
        hostname: String(item.hostname || ""),
        relayUrl: String(item.relay_url || defaultRelayUrl()),
        password: String(item.password || ""),
        favorite: !!item.favorite,
        notes: String(item.notes || ""),
        lastConnected: String(item.last_connected || ""),
        connectCount: Number(item.connect_count || 0),
        updated_at: Number(item.updated_at || Date.now()),
      });
    }

    const allKeys = new Set([
      ...localMap.keys(),
      ...remoteMap.keys(),
      ...Object.keys(localDeleted),
      ...Object.keys(remoteDeleted),
    ]);

    let localChanged = false;
    let remoteNeedsPush = false;

    for (const key of allKeys) {
      const lRec = localMap.get(key);
      const rRec = remoteMap.get(key);
      const lDel = Number(localDeleted[key] || 0);
      const rDel = Number(remoteDeleted[key] || 0);
      const lTs = Math.max(lRec ? Number(lRec.updated_at || 0) : 0, lDel);
      const rTs = Math.max(rRec ? Number(rRec.updated_at || 0) : 0, rDel);

      if (rTs > lTs) {
        if (rDel >= (rRec ? Number(rRec.updated_at || 0) : 0)) {
          if (localMap.has(key)) { localMap.delete(key); localChanged = true; }
          if (localDeleted[key] !== rDel) { localDeleted[key] = rDel; localChanged = true; }
        } else if (rRec) {
          localMap.set(key, rRec);
          delete localDeleted[key];
          localChanged = true;
        }
      } else if (lTs > rTs) {
        remoteNeedsPush = true;
      }
    }

    if (localChanged) {
      savePeers(Array.from(localMap.values()));
      saveDeleted(localDeleted);
    }
    return { localChanged, remoteNeedsPush };
  }

  async function triggerCloudSync() {
    const relayUrl = ($("inp-relay").value || "").trim() || defaultRelayUrl();
    if (!/^wss?:\/\//i.test(relayUrl)) return;
    if (syncInProgress) { syncPending = true; return; }

    syncInProgress = true;
    syncPending = false;
    setSyncLabel("☁️ Sincronizando...", "var(--warn)");

    try {
      if (!cachedVaultKeys) {
        cachedVaultKeys = await AOCrypto.deriveVaultKeys(DEFAULT_PASSWORD);
      }
      const keys = cachedVaultKeys;

      const result = await new Promise((resolve, reject) => {
        const sock = new WebSocket(relayUrl);
        let stage = "pull";
        const timer = setTimeout(() => {
          try { sock.close(); } catch {}
          reject(new Error("Tiempo de espera agotado"));
        }, 45000);

        sock.onopen = () => {
          sock.send(JSON.stringify({
            type: "vault_pull",
            vault_id: keys.vaultId,
            auth_token: keys.authToken,
          }));
        };
        sock.onerror = () => {
          clearTimeout(timer);
          reject(new Error("No se pudo conectar al servidor"));
        };
        sock.onmessage = async (ev) => {
          try {
            const msg = JSON.parse(ev.data);
            if (msg.type === "error") {
              clearTimeout(timer);
              sock.close();
              reject(new Error(msg.message || "Error de sincronización"));
              return;
            }
            if (stage === "pull" && msg.type === "vault_data") {
              let localChanged = false;
              let needsPush = false;
              if (msg.exists && msg.nonce_b64 && msg.ciphertext_b64) {
                const remoteObj = await AOCrypto.decryptVaultPayload(keys.encKey, msg.nonce_b64, msg.ciphertext_b64);
                const merged = mergeSyncPayload(remoteObj);
                localChanged = merged.localChanged;
                needsPush = merged.remoteNeedsPush;
              } else {
                needsPush = loadPeers().length > 0;
              }

              if (needsPush) {
                stage = "push";
                const payload = exportSyncPayload();
                const enc = await AOCrypto.encryptVaultPayload(keys.encKey, payload);
                sock.send(JSON.stringify({
                  type: "vault_push",
                  vault_id: keys.vaultId,
                  auth_token: keys.authToken,
                  updated_at: Date.now(),
                  nonce_b64: enc.nonceB64,
                  ciphertext_b64: enc.ciphertextB64,
                }));
              } else {
                clearTimeout(timer);
                sock.close();
                resolve({ localChanged });
              }
            } else if (stage === "push" && msg.type === "vault_saved") {
              clearTimeout(timer);
              sock.close();
              resolve({ localChanged: false });
            }
          } catch (err) {
            clearTimeout(timer);
            try { sock.close(); } catch {}
            reject(err);
          }
        };
      });

      if (result.localChanged) renderPeerList();
      setSyncLabel("☁️ Sincronizado (PC + iPhone)", "var(--success)");
      refreshPresence();
    } catch {
      setSyncLabel("☁️ Sin conexión al servidor", "var(--muted)");
    } finally {
      syncInProgress = false;
      if (syncPending) {
        syncPending = false;
        setTimeout(triggerCloudSync, 300);
      }
    }
  }

  function packJson(msgType, obj) {
    const body = encoder.encode(JSON.stringify(obj));
    const out = new Uint8Array(1 + body.length);
    out[0] = msgType;
    out.set(body, 1);
    return out;
  }

  function packFrameAck(tsMs) {
    const out = new Uint8Array(5);
    out[0] = MSG_FRAME_ACK;
    new DataView(out.buffer).setUint32(1, tsMs >>> 0, false);
    return out;
  }

  function packPing(tsMs) {
    const out = new Uint8Array(9);
    out[0] = MSG_PING;
    const dv = new DataView(out.buffer);
    dv.setUint32(1, Math.floor(tsMs / 0x100000000), false);
    dv.setUint32(5, tsMs >>> 0, false);
    return out;
  }

  function packFileChunk(tid, chunkBytes) {
    const tidBytes = encoder.encode(tid);
    const out = new Uint8Array(2 + tidBytes.length + chunkBytes.length);
    out[0] = MSG_FILE_CHUNK;
    out[1] = tidBytes.length;
    out.set(tidBytes, 2);
    out.set(chunkBytes, 2 + tidBytes.length);
    return out;
  }

  // =========================================================================
  // Estado global de sesión remota
  // =========================================================================
  let ws = null;
  let cipher = null;
  let sendChain = Promise.resolve();
  let connected = false;
  let pingTimer = null;
  let activeSessionMeta = null;

  let currentImg = null;
  let drawRect = { x: 0, y: 0, w: 1, h: 1 };
  let cursorNorm = { x: 0.5, y: 0.5 };
  let trackpadMode = true; // Trackpad por defecto: ideal para iPhone!
  let forceRotate90 = false; // Permite horizontal incluso con el bloqueo de giro del iPhone activado
  let fillHorizontalFull = true; // En horizontal ocupa 100% de ancho y 100% de alto sin franjas negras
  let immersiveMode = false;
  let lastMoveSent = 0;

  // Telemetría
  let frameCount = 0;
  let bytesCount = 0;
  let statsStart = performance.now();
  let lastFps = 0;
  let lastLatency = 0;
  let lastKbps = 0;
  let fileBannerTimer = null;

  function queueEncryptedSend(plaintextBytes) {
    if (!ws || !cipher || !connected) return Promise.resolve();
    const activeWs = ws;
    const activeCipher = cipher;
    sendChain = sendChain
      .then(async () => {
        if (!connected || ws !== activeWs || cipher !== activeCipher) return;
        const pkt = await activeCipher.encrypt(plaintextBytes);
        if (activeWs.readyState === WebSocket.OPEN) {
          activeWs.send(pkt);
        }
      })
      .catch(() => {});
    return sendChain;
  }

  function sendInput(ev) {
    if (!connected) return;
    if (ev.kind === "mouse_move") {
      const now = performance.now();
      if (now - lastMoveSent < 22) return;
      lastMoveSent = now;
    }
    queueEncryptedSend(packJson(MSG_INPUT, ev));
  }

  // =========================================================================
  // Renderizado Canvas + Cursor Trackpad
  // =========================================================================
  const canvas = $("remote-canvas");
  const ctx = canvas.getContext("2d");

  function resizeCanvas() {
    const wrap = $("canvas-wrap");
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = wrap.clientWidth || window.innerWidth;
    const h = wrap.clientHeight || window.innerHeight;
    canvas.width = Math.max(1, Math.floor(w * dpr));
    canvas.height = Math.max(1, Math.floor(h * dpr));
    renderCanvas();
  }

  function renderCanvas() {
    const cw = canvas.width;
    const ch = canvas.height;
    ctx.fillStyle = "#020617";
    ctx.fillRect(0, 0, cw, ch);
    if (!currentImg) return;

    const iw = currentImg.naturalWidth || currentImg.width;
    const ih = currentImg.naturalHeight || currentImg.height;

    if (forceRotate90) {
      // Rota el escritorio 90° horarios para aprovechar la pantalla completa en horizontal
      let dw, dh, ox, oy;
      if (fillHorizontalFull) {
        dw = ch;
        dh = cw;
        ox = 0;
        oy = 0;
      } else {
        const scale = Math.min(cw / ih, ch / iw);
        dw = Math.max(1, Math.round(iw * scale));
        dh = Math.max(1, Math.round(ih * scale));
        ox = Math.floor((cw - dh) / 2);
        oy = Math.floor((ch - dw) / 2);
      }
      drawRect = { x: ox, y: oy, w: dh, h: dw };

      ctx.save();
      ctx.translate(cw / 2, ch / 2);
      ctx.rotate(Math.PI / 2);
      ctx.drawImage(currentImg, -dw / 2, -dh / 2, dw, dh);
      if (trackpadMode) {
        const px = -dw / 2 + cursorNorm.x * dw;
        const py = -dh / 2 + cursorNorm.y * dh;
        ctx.beginPath();
        ctx.arc(px, py, 9, 0, Math.PI * 2);
        ctx.strokeStyle = "#38bdf8";
        ctx.lineWidth = 2.5;
        ctx.stroke();
      }
      ctx.restore();
      return;
    }

    const isLandscape = cw > ch;
    let ox, oy, dw, dh;
    if (isLandscape && fillHorizontalFull) {
      // En horizontal ocupa el 100% del ancho y el 100% del alto (full screen sin franjas negras)
      ox = 0;
      oy = 0;
      dw = cw;
      dh = ch;
    } else {
      const scale = Math.min(cw / iw, ch / ih);
      dw = Math.max(1, Math.round(iw * scale));
      dh = Math.max(1, Math.round(ih * scale));
      ox = Math.floor((cw - dw) / 2);
      oy = Math.floor((ch - dh) / 2);
    }
    drawRect = { x: ox, y: oy, w: dw, h: dh };

    ctx.drawImage(currentImg, ox, oy, dw, dh);

    // En modo Trackpad dibuja un aro guía sutil para ver la posición exacta del puntero
    if (trackpadMode) {
      const px = ox + cursorNorm.x * dw;
      const py = oy + cursorNorm.y * dh;
      ctx.save();
      ctx.beginPath();
      ctx.arc(px, py, 9, 0, Math.PI * 2);
      ctx.strokeStyle = "#38bdf8";
      ctx.lineWidth = 2.5;
      ctx.stroke();
      ctx.restore();
    }
  }

  function clientPointToNorm(clientX, clientY) {
    const rect = canvas.getBoundingClientRect();
    const dprX = canvas.width / Math.max(1, rect.width);
    const dprY = canvas.height / Math.max(1, rect.height);
    const cx = (clientX - rect.left) * dprX;
    const cy = (clientY - rect.top) * dprY;
    if (cx < drawRect.x || cx > drawRect.x + drawRect.w || cy < drawRect.y || cy > drawRect.y + drawRect.h) {
      return null;
    }
    const u = Math.max(0, Math.min(1, (cx - drawRect.x) / drawRect.w));
    const v = Math.max(0, Math.min(1, (cy - drawRect.y) / drawRect.h));
    if (forceRotate90) {
      // Mapeo inverso de rotación 90° horaria: x_remoto = v, y_remoto = 1 - u
      return { x: v, y: 1 - u };
    }
    return { x: u, y: v };
  }

  function setImmersive(enabled) {
    immersiveMode = !!enabled;
    $("viewer-view").classList.toggle("immersive", immersiveMode);
    $("floating-controls-btn").classList.toggle("hidden", !immersiveMode);
    setTimeout(resizeCanvas, 40);
    setTimeout(resizeCanvas, 220);
  }

  function requestNativeFullscreenIfSupported() {
    const el = $("viewer-view");
    const req = el.requestFullscreen || el.webkitRequestFullscreen;
    if (req) {
      try { req.call(el); } catch {}
    }
  }

  function exitNativeFullscreenIfActive() {
    const exit = document.exitFullscreen || document.webkitExitFullscreen;
    if (exit && (document.fullscreenElement || document.webkitFullscreenElement)) {
      try { exit.call(document); } catch {}
    }
  }

  // =========================================================================
  // Conexión WebSocket + Autenticación HMAC + AES-256-GCM
  // =========================================================================
  function setViewerStatus(state, text) {
    const dot = $("v-dot");
    dot.className = "dot" + (state === "ok" ? " ok" : state === "err" ? " err" : "");
    $("v-status").textContent = text;
    if (state === "err") {
      $("viewer-overlay-msg").textContent = text;
      $("viewer-overlay-msg").classList.remove("hidden");
    }
  }

  function openSession({ relayUrl, sessionId, pin, alias, remember }) {
    const normId = normalizeSessionId(sessionId);
    if (!relayUrl || !/^wss?:\/\//i.test(relayUrl)) {
      alert("La URL del servidor Relay debe empezar por ws:// o wss://");
      return;
    }
    if (!normId) {
      alert("Introduce el ID del PC remoto.");
      return;
    }
    if (!pin) {
      alert("Introduce la contraseña del equipo remoto.");
      return;
    }

    localStorage.setItem(RELAY_KEY, relayUrl);
    activeSessionMeta = { id: normId, alias: alias || "", relayUrl, pin, remember };

    $("console-view").classList.add("hidden");
    $("viewer-view").classList.remove("hidden");
    $("viewer-overlay-msg").textContent = "Conectando y negociando cifrado AES-256-GCM...";
    $("viewer-overlay-msg").classList.remove("hidden");
    $("v-stats").textContent = "";
    currentImg = null;
    resizeCanvas();
    setViewerStatus("warn", `Conectando a ${alias || normId}...`);

    try {
      ws = new WebSocket(relayUrl);
      ws.binaryType = "arraybuffer";
    } catch (err) {
      setViewerStatus("err", `Error abriendo WebSocket: ${err.message}`);
      return;
    }

    let derivedKeys = null;

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: "request_challenge", session_id: normId }));
    };

    ws.onerror = () => {
      if (!connected) {
        setViewerStatus("err", `No se pudo conectar al Relay (${relayUrl}).`);
      }
    };

    ws.onclose = () => {
      if (connected) {
        setViewerStatus("err", "Sesión finalizada.");
      }
      cleanupSocketOnly();
    };

    ws.onmessage = async (event) => {
      if (typeof event.data === "string") {
        let msg;
        try { msg = JSON.parse(event.data); } catch { return; }

        if (msg.type === "error") {
          setViewerStatus("err", msg.message || "Error del servidor.");
          return;
        }
        if (msg.type === "challenge") {
          setViewerStatus("warn", "Verificando contraseña...");
          try {
            const salt = AOCrypto.base64ToBytes(msg.salt_b64);
            const nonce = AOCrypto.base64ToBytes(msg.nonce_b64);
            derivedKeys = await AOCrypto.deriveSessionKeys(pin, salt);
            const proof = await AOCrypto.computeAuthProof(derivedKeys.authKey, nonce);
            ws.send(JSON.stringify({
              type: "authenticate",
              session_id: normId,
              proof_b64: proof,
            }));
          } catch (err) {
            setViewerStatus("err", `Error criptográfico: ${err.message}`);
          }
          return;
        }
        if (msg.type === "paired") {
          cipher = new AOCrypto.E2ECipher(derivedKeys.encKey);
          sendChain = Promise.resolve();
          connected = true;
          statsStart = performance.now();
          frameCount = 0;
          bytesCount = 0;
          setViewerStatus("ok", alias || normId);
          // Si ya está el iPhone en horizontal al conectar, entra directo en pantalla completa full
          if (window.innerWidth > window.innerHeight) {
            setImmersive(true);
          }
          pingTimer = setInterval(() => {
            if (connected) queueEncryptedSend(packPing(Math.round(performance.now())));
          }, 2500);
          return;
        }
        if (msg.type === "peer_disconnected") {
          setViewerStatus("err", msg.reason || "El equipo remoto se desconectó.");
          cleanupSocketOnly();
          return;
        }
      } else {
        await handleBinaryPacket(new Uint8Array(event.data));
      }
    };
  }

  async function handleBinaryPacket(packet) {
    if (!cipher || !connected) return;
    let plain;
    try {
      plain = await cipher.decrypt(packet);
    } catch {
      return;
    }
    if (!plain.length) return;
    const msgType = plain[0];
    const body = plain.subarray(1);

    if (msgType === MSG_HELLO) {
      const info = JSON.parse(decoder.decode(body));
      const hostName = info.hostname || activeSessionMeta.id;
      setViewerStatus("ok", activeSessionMeta.alias || hostName);

      // Guarda / actualiza en la agenda del iPhone automáticamente
      upsertPeer({
        id: activeSessionMeta.id,
        alias: activeSessionMeta.alias,
        hostname: hostName,
        relayUrl: activeSessionMeta.relayUrl,
        password: activeSessionMeta.pin,
        remember: activeSessionMeta.remember,
      });

      // Rellena selector de monitores
      const sel = $("v-monitor");
      sel.innerHTML = "";
      (info.monitors || []).forEach((m) => {
        const opt = document.createElement("option");
        opt.value = String(m.index);
        opt.textContent = m.index === 0 ? "Todos" : `Mon ${m.index}`;
        if (m.index === info.active_monitor) opt.selected = true;
        sel.appendChild(opt);
      });
    } else if (msgType === MSG_PONG) {
      const dv = new DataView(body.buffer, body.byteOffset, 8);
      const sentMs = dv.getUint32(0, false) * 0x100000000 + dv.getUint32(4, false);
      lastLatency = Math.max(0, Math.round(performance.now() - sentMs));
    } else if (msgType === MSG_FRAME) {
      if (body.length < 9) return;
      const dv = new DataView(body.buffer, body.byteOffset, 9);
      const tsMs = dv.getUint32(5, false);
      queueEncryptedSend(packFrameAck(tsMs));

      const jpeg = body.subarray(9);
      const blob = new Blob([jpeg], { type: "image/jpeg" });
      const url = URL.createObjectURL(blob);
      const img = new Image();
      img.onload = () => {
        URL.revokeObjectURL(url);
        currentImg = img;
        $("viewer-overlay-msg").classList.add("hidden");
        renderCanvas();
      };
      img.onerror = () => URL.revokeObjectURL(url);
      img.src = url;

      frameCount++;
      bytesCount += packet.length;
      const now = performance.now();
      const dt = (now - statsStart) / 1000;
      if (dt >= 1.0) {
        lastFps = frameCount / dt;
        lastKbps = (bytesCount / 1024) / dt;
        frameCount = 0;
        bytesCount = 0;
        statsStart = now;
        $("v-stats").textContent = `${lastFps.toFixed(0)} FPS • ${lastLatency}ms • ${lastKbps.toFixed(0)} KB/s`;
      }
    } else if (msgType === MSG_FILE_STATUS) {
      const info = JSON.parse(decoder.decode(body));
      if (info.status === "ok") {
        showFileBanner(`✔ Enviado '${info.filename}' → ${info.saved_path}`, "ok", 7000);
      } else if (info.status === "error") {
        showFileBanner(`✖ Error: ${info.message || "Transferencia fallida"}`, "err", 7000);
      }
    }
  }

  function cleanupSocketOnly() {
    connected = false;
    if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
    if (ws) {
      try { ws.close(); } catch {}
      ws = null;
    }
    cipher = null;
  }

  function closeViewer() {
    cleanupSocketOnly();
    exitNativeFullscreenIfActive();
    forceRotate90 = false;
    setImmersive(false);
    $("viewer-view").classList.add("hidden");
    $("console-view").classList.remove("hidden");
    $("ios-kb-input").blur();
    refreshPresence();
  }

  // =========================================================================
  // Transferencia de archivos desde iPhone al PC Windows
  // =========================================================================
  function showFileBanner(text, cls, autoHideMs) {
    const b = $("file-banner");
    b.textContent = text;
    b.className = cls || "";
    b.classList.remove("hidden");
    if (fileBannerTimer) clearTimeout(fileBannerTimer);
    if (autoHideMs) {
      fileBannerTimer = setTimeout(() => b.classList.add("hidden"), autoHideMs);
    }
  }

  async function sendFileToRemote(file) {
    if (!connected) return;
    const tid = Math.random().toString(16).slice(2, 14);
    const total = file.size;
    showFileBanner(`📤 Leyendo '${file.name}'...`, "", 0);

    const fullBuf = new Uint8Array(await file.arrayBuffer());
    const shaHex = await AOCrypto.sha256Hex(fullBuf);

    await queueEncryptedSend(packJson(MSG_FILE_START, {
      transfer_id: tid,
      filename: file.name,
      size: total,
    }));

    let sent = 0;
    for (let off = 0; off < fullBuf.length; off += FILE_CHUNK_SIZE) {
      if (!connected) return;
      const slice = fullBuf.subarray(off, Math.min(fullBuf.length, off + FILE_CHUNK_SIZE));
      await queueEncryptedSend(packFileChunk(tid, slice));
      sent += slice.length;
      const pct = Math.min(100, Math.round((sent * 100) / Math.max(1, total)));
      showFileBanner(`📤 Enviando '${file.name}' cifrado E2E... ${pct}%`, "", 0);
      await new Promise((r) => setTimeout(r, 4));
    }

    await queueEncryptedSend(packJson(MSG_FILE_END, {
      transfer_id: tid,
      sha256: shaHex,
    }));
  }

  // =========================================================================
  // Control Táctil iPhone (Trackpad + Toque directo + 2 dedos scroll/clic der.)
  // =========================================================================
  let touchState = {
    active: false,
    count: 0,
    startX: 0,
    startY: 0,
    lastX: 0,
    lastY: 0,
    moved: false,
    longPressTimer: null,
    directDragging: false,
  };

  canvas.addEventListener("touchstart", (e) => {
    e.preventDefault();
    if (!connected) return;
    const t = e.touches;
    touchState.active = true;
    touchState.count = t.length;
    touchState.moved = false;
    touchState.startX = t[0].clientX;
    touchState.startY = t[0].clientY;
    touchState.lastX = t[0].clientX;
    touchState.lastY = t[0].clientY;
    clearTimeout(touchState.longPressTimer);

    if (!trackpadMode && t.length === 1) {
      const norm = clientPointToNorm(t[0].clientX, t[0].clientY);
      if (norm) {
        cursorNorm = norm;
        sendInput({ kind: "mouse_move", x: norm.x, y: norm.y });
        touchState.longPressTimer = setTimeout(() => {
          if (!touchState.moved && touchState.active) {
            sendInput({ kind: "mouse_down", button: "right", x: cursorNorm.x, y: cursorNorm.y });
            sendInput({ kind: "mouse_up", button: "right", x: cursorNorm.x, y: cursorNorm.y });
            touchState.moved = true;
          }
        }, 450);
      }
    }
  }, { passive: false });

  canvas.addEventListener("touchmove", (e) => {
    e.preventDefault();
    if (!connected || !touchState.active) return;
    const t = e.touches;
    const dx = t[0].clientX - touchState.lastX;
    const dy = t[0].clientY - touchState.lastY;
    if (Math.hypot(t[0].clientX - touchState.startX, t[0].clientY - touchState.startY) > 7) {
      touchState.moved = true;
      clearTimeout(touchState.longPressTimer);
    }

    if (t.length === 2) {
      // Desplazamiento vertical con 2 dedos
      if (Math.abs(dy) > 2) {
        sendInput({ kind: "mouse_wheel", delta: Math.round(dy * 5), horizontal: false, x: cursorNorm.x, y: cursorNorm.y });
      }
    } else if (t.length === 1) {
      if (trackpadMode) {
        const rect = canvas.getBoundingClientRect();
        const sens = 1.45;
        if (forceRotate90) {
          // Con pantalla rotada 90° horarios: deslizar abajo -> derecha remota, deslizar izquierda -> abajo remoto
          cursorNorm.x = Math.max(0, Math.min(1, cursorNorm.x + (dy * sens) / Math.max(1, rect.height)));
          cursorNorm.y = Math.max(0, Math.min(1, cursorNorm.y - (dx * sens) / Math.max(1, rect.width)));
        } else {
          cursorNorm.x = Math.max(0, Math.min(1, cursorNorm.x + (dx * sens) / Math.max(1, rect.width)));
          cursorNorm.y = Math.max(0, Math.min(1, cursorNorm.y + (dy * sens) / Math.max(1, rect.height)));
        }
        sendInput({ kind: "mouse_move", x: cursorNorm.x, y: cursorNorm.y });
        renderCanvas();
      } else {
        const norm = clientPointToNorm(t[0].clientX, t[0].clientY);
        if (norm) {
          if (!touchState.directDragging) {
            touchState.directDragging = true;
            sendInput({ kind: "mouse_down", button: "left", x: cursorNorm.x, y: cursorNorm.y });
          }
          cursorNorm = norm;
          sendInput({ kind: "mouse_move", x: norm.x, y: norm.y });
        }
      }
    }

    touchState.lastX = t[0].clientX;
    touchState.lastY = t[0].clientY;
  }, { passive: false });

  canvas.addEventListener("touchend", (e) => {
    e.preventDefault();
    clearTimeout(touchState.longPressTimer);
    if (!connected || !touchState.active) return;

    if (touchState.directDragging) {
      sendInput({ kind: "mouse_up", button: "left", x: cursorNorm.x, y: cursorNorm.y });
      touchState.directDragging = false;
    } else if (!touchState.moved) {
      const btn = touchState.count >= 2 ? "right" : "left";
      sendInput({ kind: "mouse_down", button: btn, x: cursorNorm.x, y: cursorNorm.y });
      sendInput({ kind: "mouse_up", button: btn, x: cursorNorm.x, y: cursorNorm.y });
    }
    if (e.touches.length === 0) touchState.active = false;
  }, { passive: false });

  // Soporte ratón si se abre también desde navegador de escritorio/iPad con ratón
  canvas.addEventListener("mousedown", (e) => {
    const norm = clientPointToNorm(e.clientX, e.clientY);
    if (!norm) return;
    cursorNorm = norm;
    const btn = e.button === 2 ? "right" : e.button === 1 ? "middle" : "left";
    sendInput({ kind: "mouse_down", button: btn, x: norm.x, y: norm.y });
  });
  canvas.addEventListener("mouseup", (e) => {
    const norm = clientPointToNorm(e.clientX, e.clientY);
    if (!norm) return;
    cursorNorm = norm;
    const btn = e.button === 2 ? "right" : e.button === 1 ? "middle" : "left";
    sendInput({ kind: "mouse_up", button: btn, x: norm.x, y: norm.y });
  });
  canvas.addEventListener("mousemove", (e) => {
    const norm = clientPointToNorm(e.clientX, e.clientY);
    if (!norm) return;
    cursorNorm = norm;
    sendInput({ kind: "mouse_move", x: norm.x, y: norm.y });
  });
  canvas.addEventListener("contextmenu", (e) => e.preventDefault());

  // =========================================================================
  // Teclado nativo de iPhone (soporta español: ñ, tildes, Backspace, Enter)
  // =========================================================================
  const kbInput = $("ios-kb-input");
  kbInput.addEventListener("input", () => {
    const val = kbInput.value;
    kbInput.value = "";
    if (!val || !connected) return;
    for (const ch of val) {
      sendInput({ kind: "key_down", keysym: ch, char: ch, keycode: 0, platform: "ios" });
      sendInput({ kind: "key_up", keysym: ch, char: "", keycode: 0, platform: "ios" });
    }
  });
  kbInput.addEventListener("keydown", (e) => {
    if (!connected) return;
    const specialMap = {
      Backspace: "BackSpace",
      Enter: "Return",
      Tab: "Tab",
      Escape: "Escape",
      ArrowLeft: "Left",
      ArrowRight: "Right",
      ArrowUp: "Up",
      ArrowDown: "Down",
      Delete: "Delete",
    };
    const ks = specialMap[e.key];
    if (ks) {
      e.preventDefault();
      sendInput({ kind: "key_down", keysym: ks, char: "", keycode: 0, platform: "ios" });
      sendInput({ kind: "key_up", keysym: ks, char: "", keycode: 0, platform: "ios" });
    }
  });

  // =========================================================================
  // Render de la Lista de PCs + Modal Editar / Renombrar
  // =========================================================================
  let editingPeerId = null;

  function renderPeerList() {
    const q = ($("inp-search").value || "").trim().toLowerCase();
    let list = loadPeers();
    const total = list.length;
    if (q) {
      list = list.filter((p) =>
        (p.alias || "").toLowerCase().includes(q) ||
        (p.hostname || "").toLowerCase().includes(q) ||
        (p.id || "").toLowerCase().includes(q)
      );
    }
    list.sort((a, b) => (b.favorite ? 1 : 0) - (a.favorite ? 1 : 0));

    const onlineCount = list.filter((p) => {
      const s = peerPresence[p.id];
      return s === "online" || s === "busy";
    }).length;
    $("peer-count").textContent = `🟢 ${onlineCount} • ${list.length}/${total}`;
    const container = $("peer-list");
    container.innerHTML = "";

    if (!list.length) {
      container.innerHTML = `<div class="empty-state">Aún no hay equipos guardados. Conéctate a un PC arriba y aparecerá aquí automáticamente.</div>`;
      return;
    }

    list.forEach((p) => {
      const div = document.createElement("div");
      div.className = "peer-item";
      const favStar = p.favorite ? "★ " : "";
      const pwdBadge = p.password ? "🔒 Clave guardada" : "Pedir clave";
      const st = peerPresence[p.id] || "unknown";
      const isOnline = st === "online" || st === "busy";
      const ledClass = isOnline ? "led led-online" : (st === "offline" ? "led led-offline" : "led");
      const pillClass = isOnline ? "status-pill online" : (st === "offline" ? "status-pill offline" : "status-pill unknown");
      const pillText = st === "online" ? "En línea" : (st === "busy" ? "En sesión" : (st === "offline" ? "Desconectado" : "..."));
      div.innerHTML = `
        <div class="peer-top">
          <div>
            <div class="peer-name">
              <span class="${ledClass}"></span>
              <span>${escapeHtml(favStar + (p.alias || p.id))}</span>
              <span class="${pillClass}">${pillText}</span>
            </div>
            <div class="peer-meta">ID: ${escapeHtml(p.id)} • ${pwdBadge} • ${escapeHtml(p.lastConnected || "")}</div>
          </div>
          <button class="btn btn-accent btn-sm" data-act="connect">Conectar</button>
        </div>
        <div class="peer-actions">
          <button class="btn btn-sm" data-act="rename">🏷 Renombrar</button>
          <button class="btn btn-sm" data-act="fav">${p.favorite ? "★ Quitar fav" : "☆ Favorito"}</button>
          <button class="btn btn-sm" data-act="edit">✏️ Editar</button>
          <button class="btn btn-danger btn-sm" data-act="delete">🗑</button>
        </div>
      `;

      div.querySelector('[data-act="connect"]').onclick = () => {
        let pwd = p.password;
        if (!pwd) {
          pwd = prompt(`Contraseña para ${p.alias || p.id}:`, DEFAULT_PASSWORD) || "";
          if (!pwd) return;
        }
        openSession({
          relayUrl: p.relayUrl || $("inp-relay").value.trim(),
          sessionId: p.id,
          pin: pwd,
          alias: p.alias,
          remember: true,
        });
      };

      div.querySelector('[data-act="rename"]').onclick = () => {
        const next = prompt(`Nuevo nombre para ${p.id}:`, p.alias || p.id);
        if (next && next.trim()) {
          const peers = loadPeers();
          const item = peers.find((x) => x.id === p.id);
          if (item) {
            item.alias = next.trim();
            item.updated_at = Date.now();
            savePeers(peers);
            renderPeerList();
            triggerCloudSync();
          }
        }
      };

      div.querySelector('[data-act="fav"]').onclick = () => {
        const peers = loadPeers();
        const item = peers.find((x) => x.id === p.id);
        if (item) {
          item.favorite = !item.favorite;
          item.updated_at = Date.now();
          savePeers(peers);
          renderPeerList();
          triggerCloudSync();
        }
      };

      div.querySelector('[data-act="edit"]').onclick = () => openEditModal(p);

      div.querySelector('[data-act="delete"]').onclick = () => {
        if (confirm(`¿Eliminar '${p.alias || p.id}' de tu lista?`)) {
          const deleted = loadDeleted();
          deleted[p.key || makePeerKey(p.mode || "relay", p.id)] = Date.now();
          saveDeleted(deleted);
          savePeers(loadPeers().filter((x) => x.id !== p.id));
          renderPeerList();
          triggerCloudSync();
        }
      };

      container.appendChild(div);
    });
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function openEditModal(peer) {
    editingPeerId = peer.id;
    $("modal-title").textContent = `Editar equipo — ${peer.id}`;
    $("m-alias").value = peer.alias || "";
    $("m-relay").value = peer.relayUrl || defaultRelayUrl();
    $("m-pwd").value = "";
    $("modal-backdrop").classList.remove("hidden");
  }

  // =========================================================================
  // Eventos de UI e inicialización
  // =========================================================================
  $("inp-relay").value = defaultRelayUrl();
  renderPeerList();

  $("btn-toggle-pwd").onclick = () => {
    const inp = $("inp-pwd");
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    $("btn-toggle-pwd").textContent = show ? "Ocultar" : "Ver";
  };

  $("btn-connect").onclick = () => {
    openSession({
      relayUrl: $("inp-relay").value.trim(),
      sessionId: $("inp-id").value.trim(),
      pin: $("inp-pwd").value.trim(),
      alias: $("inp-alias").value.trim(),
      remember: $("chk-remember").checked,
    });
  };

  $("inp-search").addEventListener("input", renderPeerList);
  $("btn-disconnect").onclick = closeViewer;

  $("btn-fit").onclick = () => {
    fillHorizontalFull = !fillHorizontalFull;
    $("btn-fit").textContent = fillHorizontalFull ? "↔ Full" : "↔ Prop.";
    $("btn-fit").classList.toggle("btn-accent", fillHorizontalFull);
    renderCanvas();
  };

  $("btn-fullscreen").onclick = () => {
    setImmersive(!immersiveMode);
    if (immersiveMode) requestNativeFullscreenIfSupported();
    else exitNativeFullscreenIfActive();
  };

  $("floating-controls-btn").onclick = () => {
    setImmersive(false);
    exitNativeFullscreenIfActive();
  };

  $("btn-rotate").onclick = () => {
    forceRotate90 = !forceRotate90;
    $("btn-rotate").classList.toggle("btn-accent", forceRotate90);
    if (forceRotate90) {
      // Al girar a horizontal forzado, pasa a pantalla completa inmersiva automáticamente
      setImmersive(true);
    } else {
      resizeCanvas();
    }
  };

  function handleViewportChange() {
    if ($("viewer-view").classList.contains("hidden")) return;
    window.scrollTo(0, 0);
    const isLandscape = window.innerWidth > window.innerHeight;
    if (isLandscape && forceRotate90) {
      // Si el usuario giró físicamente el iPhone a horizontal, desactiva la rotación manual
      forceRotate90 = false;
      $("btn-rotate").classList.remove("btn-accent");
    }
    // Al girar el iPhone a horizontal, entra automáticamente en pantalla completa sin barras
    if (isLandscape && !immersiveMode) {
      setImmersive(true);
    }
    setTimeout(resizeCanvas, 50);
    setTimeout(resizeCanvas, 200);
    setTimeout(resizeCanvas, 450);
  }

  window.addEventListener("resize", handleViewportChange);
  window.addEventListener("orientationchange", handleViewportChange);
  if (window.visualViewport) {
    window.visualViewport.addEventListener("resize", handleViewportChange);
  }

  $("v-monitor").onchange = (e) => {
    queueEncryptedSend(packJson(MSG_SETTINGS, { monitor: parseInt(e.target.value, 10) }));
  };
  $("v-quality").onchange = (e) => {
    const p = QUALITY_PRESETS[e.target.value];
    if (p) queueEncryptedSend(packJson(MSG_SETTINGS, p));
  };

  $("dock-mode").onclick = () => {
    trackpadMode = !trackpadMode;
    $("dock-mode-lbl").textContent = trackpadMode ? "Trackpad" : "Toque";
    $("dock-mode").classList.toggle("active", trackpadMode);
    renderCanvas();
  };

  $("dock-rclick").onclick = () => {
    sendInput({ kind: "mouse_down", button: "right", x: cursorNorm.x, y: cursorNorm.y });
    sendInput({ kind: "mouse_up", button: "right", x: cursorNorm.x, y: cursorNorm.y });
  };

  $("dock-kb").onclick = () => {
    kbInput.focus();
  };

  $("dock-shortcuts").onclick = () => {
    const bar = $("shortcuts-bar");
    bar.classList.toggle("hidden");
    $("dock-shortcuts").classList.toggle("active", !bar.classList.contains("hidden"));
    resizeCanvas();
  };

  $("dock-file").onclick = () => {
    $("file-picker").value = "";
    $("file-picker").click();
  };

  $("file-picker").onchange = async (e) => {
    const files = Array.from(e.target.files || []);
    for (const f of files) {
      await sendFileToRemote(f);
    }
  };

  $("shortcuts-bar").addEventListener("click", (e) => {
    const btn = e.target.closest("button");
    if (!btn || !connected) return;
    if (btn.dataset.combo) {
      sendInput({ kind: "special_combo", combo: btn.dataset.combo });
    } else if (btn.dataset.key) {
      sendInput({ kind: "key_down", keysym: btn.dataset.key, char: "", keycode: 0, platform: "ios" });
      sendInput({ kind: "key_up", keysym: btn.dataset.key, char: "", keycode: 0, platform: "ios" });
    } else if (btn.dataset.ctrl) {
      const k = btn.dataset.ctrl;
      sendInput({ kind: "key_down", keysym: "Control_L", char: "", keycode: 0, platform: "ios" });
      sendInput({ kind: "key_down", keysym: k, char: "", keycode: 0, platform: "ios" });
      sendInput({ kind: "key_up", keysym: k, char: "", keycode: 0, platform: "ios" });
      sendInput({ kind: "key_up", keysym: "Control_L", char: "", keycode: 0, platform: "ios" });
    } else if (btn.dataset.scroll) {
      sendInput({ kind: "mouse_wheel", delta: parseInt(btn.dataset.scroll, 10), horizontal: false, x: cursorNorm.x, y: cursorNorm.y });
    }
  });

  $("m-cancel").onclick = () => $("modal-backdrop").classList.add("hidden");
  $("m-save").onclick = () => {
    const peers = loadPeers();
    const item = peers.find((x) => x.id === editingPeerId);
    if (item) {
      item.alias = $("m-alias").value.trim() || item.id;
      item.relayUrl = $("m-relay").value.trim() || defaultRelayUrl();
      const newPwd = $("m-pwd").value.trim();
      if (newPwd) item.password = newPwd;
      item.updated_at = Date.now();
      savePeers(peers);
      renderPeerList();
      triggerCloudSync();
    }
    $("modal-backdrop").classList.add("hidden");
  };

  $("btn-sync").onclick = () => { triggerCloudSync(); refreshPresence(); };
  setTimeout(triggerCloudSync, 400);
  setTimeout(refreshPresence, 900);
  setInterval(() => {
    if (!connected) refreshPresence();
  }, 8000);
  setInterval(() => {
    if (!connected) triggerCloudSync();
  }, 25000);

  // Banner de instalación PWA solo en iOS Safari cuando aún no está instalada
  const isIos = /iPhone|iPad|iPod/i.test(navigator.userAgent);
  const isStandalone = window.navigator.standalone === true || window.matchMedia("(display-mode: standalone)").matches;
  if (isIos && !isStandalone && !localStorage.getItem("ao_hide_ios_tip")) {
    $("ios-install-tip").classList.remove("hidden");
  }
  $("btn-dismiss-tip").onclick = () => {
    localStorage.setItem("ao_hide_ios_tip", "1");
    $("ios-install-tip").classList.add("hidden");
  };

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }
})();

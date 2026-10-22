/**
 * Biometric input: upload OR live capture per trait (never both).
 * Face live capture can be disabled for decryptor registration.
 */
(function (global) {
  const TYPE_LABELS = {
    fingerprint: "Fingerprint",
    face: "Face photo",
  };

  function ensureCameraModal() {
    let modal = document.getElementById("bio-camera-modal");
    if (modal) return modal;
    modal = document.createElement("div");
    modal.id = "bio-camera-modal";
    modal.className = "bio-camera-modal";
    modal.hidden = true;
    modal.innerHTML =
      '<div class="bio-camera-dialog">' +
      '<h3 class="bio-camera-title">Live capture</h3>' +
      '<p class="bio-camera-error" hidden></p>' +
      '<video class="bio-camera-video" autoplay playsinline></video>' +
      '<canvas class="bio-camera-canvas" hidden></canvas>' +
      '<img class="bio-camera-shot" alt="Captured" hidden>' +
      '<div class="bio-fp-pad" hidden>' +
      '<div class="bio-fp-glass"></div>' +
      '<p class="bio-fp-pad-label">Place your finger on the fingerprint sensor</p>' +
      "</div>" +
      '<div class="bio-camera-actions">' +
      '<button type="button" class="btn primary bio-cam-capture">Capture</button>' +
      '<button type="button" class="btn bio-cam-retake" hidden>Retake</button>' +
      '<button type="button" class="btn primary bio-cam-use" hidden>Use photo</button>' +
      '<button type="button" class="btn bio-cam-cancel">Cancel</button>' +
      "</div></div>";
    document.body.appendChild(modal);
    return modal;
  }

  function stopStream(modal) {
    const video = modal.querySelector(".bio-camera-video");
    const stream = video && video.srcObject;
    if (stream) {
      stream.getTracks().forEach(function (t) {
        t.stop();
      });
      video.srcObject = null;
    }
  }

  const FP_DEVICE_HINTS = [
    "finger",
    "u.are.u",
    "digitalpersona",
    "digital persona",
    "futronic",
    "secugen",
    "mantra",
    "morpho",
    "zkteco",
    "zkfinger",
    "fs80",
    "fs88",
    "crossmatch",
    "suprema",
    "nitgen",
    "persona",
  ];
  const WEBCAM_HINTS = [
    "webcam",
    "integrated",
    "facetime",
    "rgb",
    "infrared",
    "ir camera",
    "laptop",
    "front camera",
    "user-facing",
    "obs virtual",
  ];

  function isWebcamLabel(label) {
    const n = (label || "").toLowerCase();
    if (FP_DEVICE_HINTS.some(function (h) { return n.indexOf(h) !== -1; })) return false;
    return WEBCAM_HINTS.some(function (h) { return n.indexOf(h) !== -1; });
  }

  function isFingerprintDeviceLabel(label) {
    const n = (label || "").toLowerCase();
    if (!n || isWebcamLabel(n)) return false;
    return FP_DEVICE_HINTS.some(function (h) { return n.indexOf(h) !== -1; });
  }

  function findFingerprintVideoDevice(onDone) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
      onDone(null);
      return;
    }
    navigator.mediaDevices.enumerateDevices().then(function (devices) {
      const cams = devices.filter(function (d) { return d.kind === "videoinput"; });
      const match = cams.find(function (d) { return isFingerprintDeviceLabel(d.label); });
      onDone(match || null);
    }).catch(function () {
      onDone(null);
    });
  }

  function openCamera(title, onUse, options) {
    options = options || {};
    const isFingerprint = options.mode === "fingerprint";
    const modal = ensureCameraModal();
    const video = modal.querySelector(".bio-camera-video");
    const canvas = modal.querySelector(".bio-camera-canvas");
    const shot = modal.querySelector(".bio-camera-shot");
    const pad = modal.querySelector(".bio-fp-pad");
    const err = modal.querySelector(".bio-camera-error");
    const btnCap = modal.querySelector(".bio-cam-capture");
    const btnRetake = modal.querySelector(".bio-cam-retake");
    const btnUse = modal.querySelector(".bio-cam-use");
    const btnCancel = modal.querySelector(".bio-cam-cancel");
    modal.querySelector(".bio-camera-title").textContent = isFingerprint
      ? "Fingerprint sensor scan"
      : title || "Live capture";
    err.hidden = true;
    err.textContent = "";
    shot.hidden = true;
    pad.hidden = !isFingerprint;
    video.hidden = isFingerprint;
    btnCap.hidden = false;
    btnCap.textContent = isFingerprint ? "Scan sensor" : "Capture";
    btnUse.textContent = isFingerprint ? "Use scan" : "Use photo";
    btnRetake.hidden = true;
    btnUse.hidden = true;
    modal.hidden = false;
    let capturedData = "";

    function resetShot() {
      capturedData = "";
      shot.hidden = true;
      video.hidden = isFingerprint;
      pad.hidden = !isFingerprint;
      btnCap.hidden = false;
      btnRetake.hidden = true;
      btnUse.hidden = true;
      err.hidden = true;
    }

    function close() {
      stopStream(modal);
      modal.hidden = true;
      btnCap.onclick = null;
      btnRetake.onclick = null;
      btnUse.onclick = null;
      btnCancel.onclick = null;
    }

    function showShot(dataUrl) {
      capturedData = dataUrl;
      shot.src = dataUrl;
      shot.hidden = false;
      video.hidden = true;
      pad.hidden = true;
      btnCap.hidden = true;
      btnRetake.hidden = false;
      btnUse.hidden = false;
    }

    function scanFingerprintSensor() {
      err.hidden = true;
      btnCap.disabled = true;
      btnCap.textContent = "Scanning…";
      fetch("/api/fingerprint/sensor_scan", { method: "POST" })
        .then(function (res) {
          return res.json().then(function (body) {
            return { ok: res.ok, body: body };
          });
        })
        .then(function (result) {
          btnCap.disabled = false;
          btnCap.textContent = "Scan sensor";
          if (result.body && result.body.ok && result.body.image) {
            showShot(result.body.image);
            return;
          }
          findFingerprintVideoDevice(function (device) {
            if (!device || !device.deviceId) {
              err.hidden = false;
              err.textContent =
                (result.body && result.body.error) ||
                "No fingerprint sensor found. Connect a USB fingerprint scanner (do not use the face webcam) or upload a fingerprint image.";
              return;
            }
            navigator.mediaDevices
              .getUserMedia({ video: { deviceId: { exact: device.deviceId } }, audio: false })
              .then(function (stream) {
                pad.hidden = true;
                video.hidden = false;
                video.srcObject = stream;
                btnCap.textContent = "Capture scan";
                err.hidden = false;
                err.textContent = "Fingerprint sensor live view. Place your finger, then click Capture scan.";
              })
              .catch(function () {
                err.hidden = false;
                err.textContent =
                  "Could not open the fingerprint sensor. Use image upload instead. The face webcam will not be used.";
              });
          });
        })
        .catch(function () {
          btnCap.disabled = false;
          btnCap.textContent = "Scan sensor";
          err.hidden = false;
          err.textContent =
            "Could not reach the fingerprint sensor service. Connect a scanner or upload a fingerprint image.";
        });
    }

    if (!isFingerprint && (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia)) {
      err.hidden = false;
      err.textContent = "Camera is not available in this browser. Use image upload instead.";
      video.hidden = true;
      btnCap.hidden = true;
      btnCancel.onclick = function () {
        stopStream(modal);
        modal.hidden = true;
      };
      return;
    }

    if (!isFingerprint) {
      navigator.mediaDevices
        .getUserMedia({ video: { facingMode: "user" }, audio: false })
        .then(function (stream) {
          video.srcObject = stream;
        })
        .catch(function (e) {
          err.hidden = false;
          var name = (e && e.name) || "";
          if (name === "NotAllowedError" || name === "PermissionDeniedError") {
            err.textContent = "Camera permission denied. Allow camera access or use image upload instead.";
          } else if (name === "NotFoundError" || name === "DevicesNotFoundError") {
            err.textContent = "No camera was found. Use image upload instead.";
          } else {
            err.textContent = "Camera access denied or unavailable. Use image upload instead.";
          }
          video.hidden = true;
          btnCap.hidden = true;
        });
    }

    btnCap.onclick = function () {
      if (isFingerprint && !video.srcObject) {
        scanFingerprintSensor();
        return;
      }
      if (!video.srcObject) return;
      canvas.width = video.videoWidth || 640;
      canvas.height = video.videoHeight || 480;
      canvas.getContext("2d").drawImage(video, 0, 0, canvas.width, canvas.height);
      showShot(canvas.toDataURL("image/png"));
    };
    btnRetake.onclick = function () {
      stopStream(modal);
      resetShot();
    };
    btnUse.onclick = function () {
      if (!capturedData) return;
      onUse(capturedData);
      close();
    };
    btnCancel.onclick = close;
  }

  function usedTypes(container) {
    const used = new Set();
    container.querySelectorAll(".bio-slot").forEach(function (slot) {
      const t = slot.dataset.type || (slot.querySelector(".bio-type-select") || {}).value;
      if (t) used.add(t);
    });
    return used;
  }

  function updatePills(container) {
    const pills = container.querySelector(".bio-type-pills");
    if (!pills) return;
    pills.innerHTML = "";
    ["fingerprint", "face"].forEach(function (t) {
      const pill = document.createElement("span");
      pill.className = "bio-type-pill" + (usedTypes(container).has(t) ? " done" : "");
      pill.textContent = TYPE_LABELS[t];
      pills.appendChild(pill);
    });
  }

  function updateAddButton(container) {
    const addBtn = container.querySelector(".btn-add-bio");
    if (!addBtn) return;
    const max = parseInt(container.dataset.maxSlots || "3", 10);
    addBtn.disabled = container.querySelectorAll(".bio-slot").length >= max;
  }

  function setSelectedLabel(slot, source) {
    const el = slot.querySelector(".bio-selected-source");
    if (!el) return;
    if (source === "live") el.textContent = "Selected: Live capture";
    else if (source === "upload") el.textContent = "Selected: Uploaded image";
    else el.textContent = "Selected: none";
  }

  function previewFromFile(slot, file) {
    const img = slot.querySelector(".bio-preview-img");
    const wrap = slot.querySelector(".bio-preview");
    if (!img || !wrap || !file) return;
    const reader = new FileReader();
    reader.onload = function () {
      img.src = reader.result;
      wrap.hidden = false;
    };
    reader.readAsDataURL(file);
  }

  function applyLive(slot, dataUrl) {
    const liveInput = slot.querySelector(".bio-live-input");
    const sourceInput = slot.querySelector(".bio-source-input");
    const fileInput = slot.querySelector(".bio-file-input");
    if (liveInput) liveInput.value = dataUrl;
    if (sourceInput) sourceInput.value = "live";
    if (fileInput) fileInput.value = "";
    const img = slot.querySelector(".bio-preview-img");
    const wrap = slot.querySelector(".bio-preview");
    if (img && wrap) {
      img.src = dataUrl;
      wrap.hidden = false;
    }
    setSelectedLabel(slot, "live");
  }

  function applyUpload(slot, file) {
    const liveInput = slot.querySelector(".bio-live-input");
    const sourceInput = slot.querySelector(".bio-source-input");
    if (liveInput) liveInput.value = "";
    if (sourceInput) sourceInput.value = "upload";
    previewFromFile(slot, file);
    setSelectedLabel(slot, "upload");
  }

  function faceLiveAllowed(slot, config) {
    const type = slot.dataset.type;
    if (type !== "face") return slot.dataset.live !== "0";
    if (config && config.faceLiveCapture === false) return false;
    return slot.dataset.live !== "0";
  }

  function buildModernSlot(container, prefix, spec, config) {
    const type = spec.type;
    const liveOk = spec.liveCapture !== false && (type !== "face" || config.faceLiveCapture !== false);
    const slot = document.createElement("div");
    slot.className = "bio-slot bio-slot-or";
    slot.dataset.type = type;
    slot.dataset.required = spec.required ? "1" : "0";
    slot.dataset.live = liveOk ? "1" : "0";

    const title =
      type === "fingerprint" ? "FINGERPRINT" : "FACE";
    const hint = liveOk
      ? type === "fingerprint"
        ? "Upload a fingerprint image, or scan from a fingerprint sensor (not the face camera)"
        : "Choose one method: Upload or Live Capture"
      : type === "face"
        ? "Upload Face Image Only (live capture is not available for this face registration)"
        : "Upload an image";

    slot.innerHTML =
      '<div class="bio-slot-head">' +
      "<strong>" +
      title +
      "</strong>" +
      '<span class="bio-selected-source">Selected: none</span>' +
      "</div>" +
      '<p class="bio-or-hint">' +
      hint +
      "</p>" +
      '<div class="bio-or-row">' +
      '<div class="bio-method"><button type="button" class="btn-upload-bio">Upload Image</button>' +
      '<input type="file" class="bio-file-input bio-hidden-file" accept="image/*"></div>' +
      (liveOk
        ? '<span class="bio-or-label">OR</span>' +
          '<div class="bio-method"><button type="button" class="btn-live-bio">' +
          (type === "fingerprint" ? "Scan Sensor" : "Capture Live") +
          "</button></div>"
        : "") +
      "</div>" +
      '<div class="bio-preview" hidden><img class="bio-preview-img" alt="Selected biometric">' +
      '<button type="button" class="btn-retake-bio">Retake / Change</button></div>' +
      '<input type="hidden" class="bio-source-input">' +
      '<input type="hidden" class="bio-live-input">';

    const fileInput = slot.querySelector(".bio-file-input");
    const sourceInput = slot.querySelector(".bio-source-input");
    const liveInput = slot.querySelector(".bio-live-input");
    fileInput.name = prefix + type;
    sourceInput.name = prefix + type + "_source";
    liveInput.name = prefix + type + "_live";

    slot.querySelector(".btn-upload-bio").addEventListener("click", function () {
      fileInput.click();
    });
    fileInput.addEventListener("change", function () {
      if (fileInput.files && fileInput.files[0]) applyUpload(slot, fileInput.files[0]);
    });
    const liveBtn = slot.querySelector(".btn-live-bio");
    if (liveBtn) {
      liveBtn.addEventListener("click", function () {
        openCamera("Capture " + title.toLowerCase(), function (dataUrl) {
          applyLive(slot, dataUrl);
        }, { mode: type === "fingerprint" ? "fingerprint" : "face" });
      });
    }
    slot.querySelector(".btn-retake-bio").addEventListener("click", function () {
      fileInput.value = "";
      liveInput.value = "";
      sourceInput.value = "";
      slot.querySelector(".bio-preview").hidden = true;
      setSelectedLabel(slot, "");
    });
    container.querySelector(".bio-slots").appendChild(slot);
  }

  function syncFileInputName(slot, prefix) {
    const typeSel = slot.querySelector(".bio-type-select");
    if (!typeSel) return;
    const fileInput = slot.querySelector(".bio-file-input");
    fileInput.name = prefix + typeSel.value;
  }

  function addLegacySlot(container, prefix, options) {
    const template = container.querySelector("template.bio-slot-template");
    if (!template || !template.content) return;
    const slot = template.content.cloneNode(true).querySelector(".bio-slot");
    const slotsEl = container.querySelector(".bio-slots");
    slotsEl.appendChild(slot);
    const typeSel = slot.querySelector(".bio-type-select");
    const fileInput = slot.querySelector(".bio-file-input");
    const removeBtn = slot.querySelector(".btn-remove-bio");
    if (options.initialType) typeSel.value = options.initialType;
    if (options.required) {
      slot.dataset.required = "1";
      if (removeBtn) removeBtn.hidden = true;
    }
    typeSel.addEventListener("change", function () {
      syncFileInputName(slot, prefix);
      updatePills(container);
    });
    syncFileInputName(slot, prefix);
    if (removeBtn) {
      removeBtn.addEventListener("click", function () {
        if (slot.dataset.required === "1") return;
        slot.remove();
        updatePills(container);
        updateAddButton(container);
      });
    }
  }

  function slotHasInput(slot) {
    const fileInput = slot.querySelector(".bio-file-input");
    const liveInput = slot.querySelector(".bio-live-input");
    const source = (slot.querySelector(".bio-source-input") || {}).value;
    if (source === "live" && liveInput && liveInput.value) return true;
    if (source === "upload" && fileInput && fileInput.files && fileInput.files.length) return true;
    if (liveInput && liveInput.value) return true;
    if (fileInput && fileInput.files && fileInput.files.length) return true;
    return false;
  }

  function initBiometricPickerOnElement(container, prefix, config) {
    if (!container) return;
    if (container.dataset.pickerInit === "1") return;
    container.dataset.pickerInit = "1";
    config = config || {};
    container.dataset.maxSlots = String(config.maxSlots || 3);
    container.dataset.requireAny = config.requireAny ? "1" : "0";
    const slotsEl = container.querySelector(".bio-slots");
    slotsEl.innerHTML = "";
    const modern = config.mode === "or" || config.requiredTypes;

    if (modern) {
      const hint = container.querySelector(".bio-upload-hint");
      if (hint && config.hint) hint.textContent = config.hint;
      (config.initialSlots || []).forEach(function (spec) {
        buildModernSlot(container, prefix, spec, config);
      });
    } else {
      (config.initialSlots || [{ type: "fingerprint", required: true }]).forEach(function (spec) {
        addLegacySlot(container, prefix, { initialType: spec.type, required: spec.required });
      });
    }

    const addBtn = container.querySelector(".btn-add-bio");
    if (addBtn) {
      addBtn.addEventListener("click", function () {
        const used = usedTypes(container);
        const order = ["face", "fingerprint"];
        const next = order.find(function (t) {
          return !used.has(t);
        });
        if (!next) return;
        if (modern) {
          const live = next === "face" ? config.faceLiveCapture !== false : true;
          buildModernSlot(container, prefix, { type: next, required: false, liveCapture: live }, config);
        } else {
          addLegacySlot(container, prefix, { initialType: next, required: false });
        }
        updatePills(container);
        updateAddButton(container);
      });
    }

    const form = container.closest("form");
    if (form && !form.dataset.bioSubmitBound) {
      form.dataset.bioSubmitBound = "1";
      form.addEventListener("submit", function (ev) {
        form.querySelectorAll(".bio-upload-section").forEach(function (sec) {
          sec.querySelectorAll(".bio-slot-or[data-required='1']").forEach(function (slot) {
            if (!slotHasInput(slot)) {
              ev.preventDefault();
              alert(
                "Provide " +
                  (slot.dataset.type || "biometric") +
                  " using either Upload or Live Capture (one method only)."
              );
            }
          });
          if (sec.dataset.requireAny === "1") {
            var hasFpOrFace = false;
            sec.querySelectorAll(".bio-slot-or").forEach(function (slot) {
              var t = slot.dataset.type;
              if ((t === "fingerprint" || t === "face") && slotHasInput(slot)) hasFpOrFace = true;
            });
            if (!hasFpOrFace) {
              ev.preventDefault();
              alert("Provide fingerprint, face, or both (upload or live capture).");
            }
          }
        });
      });
    }

    updatePills(container);
    updateAddButton(container);
  }

  function initBiometricPicker(containerId, prefix, config) {
    const container =
      typeof containerId === "string" ? document.getElementById(containerId) : containerId;
    initBiometricPickerOnElement(container, prefix, config);
  }

  global.initBiometricPicker = initBiometricPicker;
  global.initBiometricPickerOnElement = initBiometricPickerOnElement;
})(window);

/**
 * Biometric upload: one file input per slot; name set from type (fingerprint / iris / face).
 */
(function (global) {
  const TYPE_LABELS = {
    fingerprint: "Fingerprint",
    iris: "Iris / eye photo",
    face: "Face photo",
  };

  function usedTypes(container) {
    const used = new Set();
    container.querySelectorAll(".bio-type-select").forEach(function (sel) {
      used.add(sel.value);
    });
    return used;
  }

  function refreshTypeOptions(container) {
    const used = usedTypes(container);
    container.querySelectorAll(".bio-type-select").forEach(function (sel) {
      const current = sel.value;
      sel.querySelectorAll("option").forEach(function (opt) {
        opt.disabled = used.has(opt.value) && opt.value !== current;
      });
    });
    updatePills(container);
    updateAddButton(container);
  }

  function updatePills(container) {
    const pills = container.querySelector(".bio-type-pills");
    if (!pills) return;
    pills.innerHTML = "";
    ["fingerprint", "iris", "face"].forEach(function (t) {
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

  function syncFileInputName(slot, prefix) {
    const type = slot.querySelector(".bio-type-select").value;
    const fileInput = slot.querySelector(".bio-file-input");
    fileInput.name = prefix + type;
  }

  function wireSlot(container, slot, prefix, options) {
    const typeSel = slot.querySelector(".bio-type-select");
    const fileInput = slot.querySelector(".bio-file-input");
    const removeBtn = slot.querySelector(".btn-remove-bio");
    const isRequired = slot.dataset.required === "1";

    typeSel.addEventListener("change", function () {
      refreshTypeOptions(container);
      syncFileInputName(slot, prefix);
    });

    fileInput.addEventListener("change", function () {
      syncFileInputName(slot, prefix);
    });

    if (removeBtn) {
      removeBtn.addEventListener("click", function () {
        if (isRequired && container.querySelectorAll(".bio-slot").length === 1) return;
        slot.remove();
        refreshTypeOptions(container);
        updateAddButton(container);
      });
    }

    if (options.initialType) typeSel.value = options.initialType;
    if (isRequired) removeBtn.hidden = true;
    syncFileInputName(slot, prefix);
  }

  function getSlotTemplate(container) {
    const local = container.querySelector("template.bio-slot-template");
    if (local && local.content && local.content.querySelector(".bio-slot")) {
      return local;
    }
    return document.getElementById("bio-slot-row-template");
  }

  function addSlot(container, prefix, options) {
    const template = getSlotTemplate(container);
    if (!template || !template.content) return;
    const slot = template.content.cloneNode(true).querySelector(".bio-slot");
    if (!slot) return;
    const slotsEl = container.querySelector(".bio-slots");
    if (!slotsEl) return;
    slotsEl.appendChild(slot);
    wireSlot(container, slot, prefix, options || {});
    refreshTypeOptions(container);
    updateAddButton(container);
  }

  function initBiometricPickerOnElement(container, prefix, config) {
    if (!container) return;
    if (container.dataset.pickerInit === "1") return;
    container.dataset.pickerInit = "1";

    config = config || {};
    container.dataset.maxSlots = String(config.maxSlots || 3);
    const slotsEl = container.querySelector(".bio-slots");
    slotsEl.innerHTML = "";

    (config.initialSlots || [{ type: "fingerprint", required: true }]).forEach(function (spec) {
      addSlot(container, prefix, { initialType: spec.type });
      const slot = slotsEl.lastElementChild;
      if (spec.required) slot.dataset.required = "1";
    });

    const addBtn = container.querySelector(".btn-add-bio");
    if (addBtn) {
      addBtn.addEventListener("click", function () {
        const used = usedTypes(container);
        let next = "iris";
        if (!used.has("iris")) next = "iris";
        else if (!used.has("face")) next = "face";
        else if (!used.has("fingerprint")) next = "fingerprint";
        addSlot(container, prefix, { initialType: next });
      });
    }

    const form = container.closest("form");
    if (form) {
      form.addEventListener("submit", function () {
        container.querySelectorAll(".bio-slot").forEach(function (slot) {
          syncFileInputName(slot, prefix);
        });
      });
    }

    refreshTypeOptions(container);
  }

  function initBiometricPicker(containerId, prefix, config) {
    const container =
      typeof containerId === "string"
        ? document.getElementById(containerId)
        : containerId;
    initBiometricPickerOnElement(container, prefix, config);
  }

  global.initBiometricPicker = initBiometricPicker;
  global.initBiometricPickerOnElement = initBiometricPickerOnElement;
})(window);

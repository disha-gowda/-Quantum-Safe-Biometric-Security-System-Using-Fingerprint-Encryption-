/**
 * QSBAC Live Cryptographic Intelligence Dashboard
 * Grouped comparison charts + dynamic API data (no hardcoded metrics).
 */
(function () {
  const root = document.getElementById("intel-dashboard");
  if (!root) return;

  const sessionId = parseInt(root.dataset.sessionId, 10);
  const POLL_MS = 4000;
  const ALGO_COLORS = {
    AES: "#ff9f43",
    DES: "#ff6b6b",
    Blowfish: "#ffd166",
    ChaCha20: "#a855f7",
    QSBAC: "#00f5ff",
  };
  const ALGO_ORDER = ["QSBAC", "AES", "DES", "Blowfish", "ChaCha20"];

  const charts = {};
  let lastTimestamp = 0;

  function api(path) {
    return fetch(path).then((r) => {
      if (!r.ok) throw new Error(r.statusText);
      return r.json();
    });
  }

  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  function sortAlgos(labels) {
    return [...labels].sort((a, b) => {
      const ia = ALGO_ORDER.indexOf(a);
      const ib = ALGO_ORDER.indexOf(b);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
    });
  }

  function baseOptions(yLabel, legend = true) {
    return {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 700, easing: "easeOutQuart" },
      interaction: { mode: "index", intersect: false },
      scales: {
        x: {
          ticks: { color: "#8ec8e8", font: { size: 10 } },
          grid: { color: "rgba(0, 245, 255, 0.06)" },
        },
        y: {
          beginAtZero: true,
          ticks: { color: "#8ec8e8" },
          grid: { color: "rgba(0, 245, 255, 0.08)" },
          title: { display: !!yLabel, text: yLabel, color: "#7ee8ff" },
        },
      },
      plugins: {
        legend: {
          display: legend,
          position: "bottom",
          labels: { color: "#b8dce8", boxWidth: 12, padding: 14, font: { size: 10 } },
        },
        tooltip: {
          backgroundColor: "rgba(5, 15, 30, 0.95)",
          borderColor: "#00f5ff",
          borderWidth: 1,
        },
      },
    };
  }

  /** Grouped bar: metrics on X-axis, one dataset per algorithm (reference style). */
  function makeGroupedBarChart(canvasId, metricLabels, yLabel) {
    const ctx = document.getElementById(canvasId);
    if (!ctx || typeof Chart === "undefined") return null;
    return new Chart(ctx, {
      type: "bar",
      data: { labels: metricLabels, datasets: [] },
      options: {
        ...baseOptions(yLabel),
        scales: {
          ...baseOptions(yLabel).scales,
          x: { ...baseOptions().scales.x, stacked: false },
        },
      },
    });
  }

  /** Per-algorithm colored bars (algorithms on X-axis). */
  function makeAlgoBarChart(canvasId, yLabel) {
    const ctx = document.getElementById(canvasId);
    if (!ctx || typeof Chart === "undefined") return null;
    return new Chart(ctx, {
      type: "bar",
      data: { labels: [], datasets: [{ label: yLabel, data: [], backgroundColor: [], borderRadius: 4 }] },
      options: baseOptions(yLabel, false),
    });
  }

  function datasetsFromComparison(comp, metricKeys, metricLabels) {
    const labels = sortAlgos(comp.labels || []);
    return labels.map((algo) => {
      const idx = (comp.labels || []).indexOf(algo);
      const data = metricKeys.map((key) => (comp[key] && comp[key][idx] != null ? comp[key][idx] : 0));
      return {
        label: algo,
        data,
        backgroundColor: ALGO_COLORS[algo] || "#888",
        borderColor: ALGO_COLORS[algo] || "#888",
        borderWidth: 1,
        borderRadius: 4,
      };
    });
  }

  function updateGroupedChart(chart, comp, metricKeys, metricLabels) {
    if (!chart || !comp) return;
    chart.data.labels = metricLabels;
    chart.data.datasets = datasetsFromComparison(comp, metricKeys, metricLabels);
    chart.update("active");
  }

  function updateAlgoBarChart(chart, comp, key, label) {
    if (!chart || !comp) return;
    const labels = sortAlgos(comp.labels || []);
    chart.data.labels = labels;
    chart.data.datasets[0].label = label;
    chart.data.datasets[0].data = labels.map((algo) => {
      const idx = comp.labels.indexOf(algo);
      return comp[key]?.[idx] ?? 0;
    });
    chart.data.datasets[0].backgroundColor = labels.map((a) => ALGO_COLORS[a] || "#666");
    chart.update("active");
  }

  function initCharts() {
    charts["chart-security-grouped"] = makeGroupedBarChart(
      "chart-security-grouped",
      ["Entropy", "NPCR (%)", "UACI (%)", "NIST Pass (%)"],
      "Score"
    );
    charts["chart-performance-grouped"] = makeGroupedBarChart(
      "chart-performance-grouped",
      ["Encrypt (s)", "Decrypt (s)", "Throughput (B/s)"],
      "Value"
    );

    const singleMetrics = [
      ["chart-entropy", "Entropy", "entropy", "bits/byte"],
      ["chart-npcr", "NPCR", "npcr", "%"],
      ["chart-uaci", "UACI", "uaci", "%"],
      ["chart-nist", "NIST Pass", "nist_pass_rate", "%"],
      ["chart-enc-time", "Encrypt", "encrypt_seconds", "s"],
      ["chart-dec-time", "Decrypt", "decrypt_seconds", "s"],
      ["chart-throughput", "Throughput", "throughput_bps", "B/s"],
      ["chart-stress", "Stress", "security_stress", "index"],
    ];
    singleMetrics.forEach(([id, label, key, yLabel]) => {
      charts[id] = makeAlgoBarChart(id, yLabel);
      charts[id]._metricKey = key;
      charts[id]._metricLabel = label;
    });

    const distCtx = document.getElementById("chart-entropy-dist");
    if (distCtx) {
      charts["chart-entropy-dist"] = new Chart(distCtx, {
        type: "line",
        data: { labels: Array.from({ length: 32 }, (_, i) => String(i)), datasets: [] },
        options: {
          ...baseOptions("Count"),
          elements: { line: { tension: 0.35 }, point: { radius: 0 } },
        },
      });
    }

    const avCtx = document.getElementById("chart-avalanche-lines");
    if (avCtx) {
      charts["chart-avalanche-lines"] = new Chart(avCtx, {
        type: "line",
        data: {
          labels: sortAlgos([]),
          datasets: [
            {
              label: "Ideal 50%",
              data: [],
              borderColor: "rgba(255,255,255,0.35)",
              borderDash: [6, 4],
              pointRadius: 0,
              fill: false,
            },
          ],
        },
        options: {
          ...baseOptions("Avalanche %"),
          scales: {
            ...baseOptions().scales,
            y: { ...baseOptions().scales.y, max: 100 },
          },
        },
      });
    }

    const trendCtx = document.getElementById("chart-stress-trend");
    if (trendCtx) {
      charts["chart-stress-trend"] = new Chart(trendCtx, {
        type: "line",
        data: { labels: [], datasets: [] },
        options: {
          ...baseOptions("Stress Index"),
          elements: { point: { radius: 3, hoverRadius: 5 } },
        },
      });
    }
  }

  function updateComparisonCharts(comp) {
    if (!comp) return;

    updateGroupedChart(
      charts["chart-security-grouped"],
      comp,
      ["entropy", "npcr", "uaci", "nist_pass_rate"],
      ["Entropy", "NPCR (%)", "UACI (%)", "NIST Pass (%)"]
    );
    updateGroupedChart(
      charts["chart-performance-grouped"],
      comp,
      ["encrypt_seconds", "decrypt_seconds", "throughput_bps"],
      ["Encrypt (s)", "Decrypt (s)", "Throughput (B/s)"]
    );

    Object.keys(charts).forEach((id) => {
      const c = charts[id];
      if (c?._metricKey) updateAlgoBarChart(c, comp, c._metricKey, c._metricLabel);
    });

    const avChart = charts["chart-avalanche-lines"];
    if (avChart && comp.labels) {
      const labels = sortAlgos(comp.labels);
      avChart.data.labels = labels;
      const ideal = labels.map(() => 50);
      const algoLines = labels.map((algo) => {
        const idx = comp.labels.indexOf(algo);
        return comp.avalanche_1bit?.[idx] ?? 0;
      });
      avChart.data.datasets = [
        {
          label: "Ideal 50%",
          data: ideal,
          borderColor: "rgba(255,255,255,0.35)",
          borderDash: [6, 4],
          pointRadius: 0,
          fill: false,
        },
        {
          label: "1-bit Avalanche",
          data: algoLines,
          borderColor: "#00f5ff",
          backgroundColor: "rgba(0,245,255,0.2)",
          fill: true,
          tension: 0.3,
          pointRadius: 5,
          pointBackgroundColor: labels.map((a) => ALGO_COLORS[a]),
        },
      ];
      avChart.update("active");
    }

    const distChart = charts["chart-entropy-dist"];
    if (distChart && comp.histogram_by_algo) {
      const algos = sortAlgos(Object.keys(comp.histogram_by_algo));
      distChart.data.datasets = algos.map((algo) => ({
        label: algo,
        data: comp.histogram_by_algo[algo] || [],
        borderColor: ALGO_COLORS[algo],
        backgroundColor: (ALGO_COLORS[algo] || "#888") + "44",
        fill: true,
        tension: 0.35,
        pointRadius: 0,
      }));
      distChart.update("active");
    }
  }

  function updateStressTrend(history, comp) {
    const c = charts["chart-stress-trend"];
    if (!c || !history?.length) return;
    const labels = history.map((_, i) => "T" + (i + 1));
    const trackAlgos = sortAlgos(comp?.labels || ["QSBAC", "AES", "ChaCha20"]).slice(0, 5);
    c.data.labels = labels;
    c.data.datasets = trackAlgos.map((algo) => ({
      label: algo + " Intelligence",
      data: history.map((h) => h.by_algo?.[algo]?.intelligence ?? h.by_algo?.[algo]?.stress ?? 0),
      borderColor: ALGO_COLORS[algo],
      backgroundColor: (ALGO_COLORS[algo] || "#888") + "22",
      tension: 0.35,
      fill: false,
      pointRadius: 2,
    }));
    c.update("active");
  }

  function updateTelemetryPanel(data) {
    const q = data.algorithms?.QSBAC || data.algorithms?.AES || data.primary || {};
    setText("tel-size", q.ciphertext_size ?? "—");
    setText("tel-blocks", q.block_count ?? "—");
    setText("tel-keylen", q.key_length_bits ? q.key_length_bits + " bits" : "—");
    setText("tel-sha256", q.sha256 ? q.sha256.slice(0, 32) + "…" : "—");
    setText("tel-hex", q.hex_preview || "—");
    setText("tel-entropy", q.entropy != null ? q.entropy.toFixed(4) + " bits/byte" : "—");
    setText("tel-uniformity", q.histogram_uniformity != null ? (q.histogram_uniformity * 100).toFixed(1) + "%" : "—");
    setText("tel-enc", q.encrypt_seconds != null ? q.encrypt_seconds.toFixed(6) + " s" : "—");
    setText("tel-dec", q.decrypt_seconds != null ? q.decrypt_seconds.toFixed(6) + " s" : "—");
    setText("tel-throughput", q.throughput_bps != null ? q.throughput_bps.toFixed(0) + " B/s" : "—");
    setText("tel-avalanche", q.avalanche_1bit != null ? q.avalanche_1bit.toFixed(2) + "%" : "—");
    setText("tel-rating", q.security_rating || "—");
    setText("tel-session", "SESSION #" + sessionId);

    const gauge = document.getElementById("gauge-entropy");
    if (gauge && q.entropy != null) {
      const pct = Math.min(100, (q.entropy / 8) * 100);
      gauge.style.setProperty("--pct", pct + "%");
      const gv = gauge.querySelector(".gauge-val");
      if (gv) gv.textContent = q.entropy.toFixed(3);
    }
  }

  function renderSbox(sbox) {
    const grid = document.getElementById("sbox-grid");
    if (!grid || !sbox?.matrix) return;
    grid.innerHTML = "";
    sbox.matrix.forEach((row) => {
      row.forEach((val) => {
        const cell = document.createElement("div");
        cell.className = "sbox-cell";
        const intensity = val / 255;
        cell.style.background = `rgba(0, 245, 255, ${0.1 + intensity * 0.7})`;
        cell.title = String(val);
        cell.textContent = (val & 0x0f).toString(16);
        grid.appendChild(cell);
      });
    });
    setText("sbox-entropy", sbox.biometric_entropy?.toFixed(4) ?? "—");
  }

  function renderAttacks(sim) {
    const tbody = document.getElementById("attack-tbody");
    if (!tbody || !sim?.attacks) return;
    tbody.innerHTML = sim.attacks
      .map(
        (a) =>
          `<tr><td>${a.name}</td><td>${a.success_rate}%</td><td>${a.detection_probability}%</td><td>${a.protection_level}%</td></tr>`
      )
      .join("");
    setText("mitigation-score", sim.mitigation_score?.toFixed(1) ?? "—");
    setText("quantum-indicator", sim.quantum_safe_indicator?.toFixed(1) ?? "—");
    const ring = document.getElementById("protection-ring");
    if (ring && sim.overall_protection != null) {
      ring.style.setProperty("--pct", sim.overall_protection + "%");
    }
  }

  function renderResearch(research) {
    const el = document.getElementById("research-conclusions");
    const rank = document.getElementById("research-rankings");
    if (!research) return;
    if (el && research.conclusions) {
      el.innerHTML = research.conclusions.map((c) => `<p class="conclusion-item">${c}</p>`).join("");
    }
    if (rank && research.rankings) {
      rank.innerHTML = research.rankings
        .map((r) => `<li><strong>${r.metric}</strong>: ${r.winner} (${r.value})</li>`)
        .join("");
    }
    const ws = document.getElementById("weighted-scores");
    if (ws && research.weighted_scores) {
      ws.innerHTML = Object.entries(research.weighted_scores)
        .sort((a, b) => b[1] - a[1])
        .map(([algo, score]) => `<li><strong>${algo}</strong>: ${score.toFixed(1)} / 100</li>`)
        .join("");
    }
    const weights = document.getElementById("scoring-weights");
    if (weights && research.scoring_model) {
      const m = research.scoring_model;
      weights.innerHTML =
        "<small>Weights: Entropy " +
        (m.entropy * 100).toFixed(0) +
        "%, NPCR " +
        (m.npcr * 100).toFixed(0) +
        "%, UACI " +
        (m.uaci * 100).toFixed(0) +
        "%, Adaptive " +
        (m.adaptive_security * 100).toFixed(0) +
        "%, Session " +
        (m.session_uniqueness * 100).toFixed(0) +
        "%, Throughput " +
        (m.throughput * 100).toFixed(0) +
        "%</small>";
    }
    const ex = document.getElementById("qsbac-exclusive");
    if (ex && research.qsbac_exclusive) {
      ex.innerHTML = Object.entries(research.qsbac_exclusive)
        .map(
          ([k, v]) =>
            `<div class="tel-stat"><span>${k.replace(/_/g, " ")}</span><strong>${v}</strong></div>`
        )
        .join("");
    }
    setText("research-summary", research.summary || "");
    setText("research-winner", research.overall_winner || "—");
  }

  function updateCyberMeters(data) {
    const tel = data.qsbac_telemetry || {};
    setText("meter-bio", tel.biometric_verified ? "VERIFIED" : "PENDING");
    setText("meter-key", tel.adaptive_key_status || "—");
    setText("meter-quantum", tel.quantum_entropy_active ? "ACTIVE" : "STANDBY");
    setText("meter-decrypts", String(data.decrypt_events ?? 0));
    document.getElementById("pulse-radar")?.classList.toggle("active", !!tel.biometric_verified);
    setText("live-status", "LIVE · " + (data.elapsed_ms || 0) + "ms");
    if (data.timestamp && data.timestamp !== lastTimestamp) {
      lastTimestamp = data.timestamp;
      const scan = document.getElementById("scan-line");
      scan?.classList.remove("pulse-once");
      void scan?.offsetWidth;
      scan?.classList.add("pulse-once");
    }
  }

  async function refresh() {
    try {
      const data = await api(`/api/live_metrics/${sessionId}`);
      updateComparisonCharts(data.comparison);
      updateTelemetryPanel(data);
      updateStressTrend(data.history, data.comparison);
      renderSbox(data.sbox);
      renderAttacks(data.attack_simulation);
      renderResearch(data.research);
      updateCyberMeters(data);
    } catch (e) {
      setText("live-status", "SYNC ERROR");
      console.error(e);
    }
  }

  initCharts();
  refresh();
  setInterval(refresh, POLL_MS);

  document.getElementById("btn-refresh-bench")?.addEventListener("click", () => {
    fetch(`/api/benchmark_refresh/${sessionId}`, { method: "POST" }).then(() => refresh());
  });
})();

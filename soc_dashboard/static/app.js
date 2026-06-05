function getValue(id) {
  return document.getElementById(id).value || "";
}

function percent(x) {
  return (x * 100).toFixed(2) + "%";
}

function renderTopK(id, rows) {
  const tbody = document.getElementById(id);
  tbody.innerHTML = "";

  rows.forEach((row, index) => {
    const tr = document.createElement("tr");

    tr.innerHTML = `
      <td>${index + 1}</td>
      <td>${row.label}</td>
      <td>${percent(row.confidence)}</td>
    `;

    tbody.appendChild(tr);
  });
}

function renderLLM(explanation) {
  const box = document.getElementById("llmBox");

  if (!explanation || explanation.summary === undefined) {
    box.innerHTML = "<p>LLM explanation unavailable.</p>";
    return;
  }

  box.innerHTML = `
    <h3>Summary</h3>
    <p>${explanation.summary || ""}</p>

    <h3>Attack Interpretation</h3>
    <p>${explanation.attack_interpretation || ""}</p>

    <h3>Why Prediction Makes Sense</h3>
    <ul>${(explanation.why_prediction_makes_sense || []).map(x => `<li>${x}</li>`).join("")}</ul>

    <h3>Confidence Interpretation</h3>
    <p>${explanation.confidence_interpretation || ""}</p>

    <h3>Triage Priority</h3>
    <p><strong>${explanation.triage_priority || ""}</strong></p>

    <h3>Recommended Triage Steps</h3>
    <ul>${(explanation.recommended_triage_steps || []).map(x => `<li>${x}</li>`).join("")}</ul>

    <h3>False Positive Checks</h3>
    <ul>${(explanation.false_positive_checks || []).map(x => `<li>${x}</li>`).join("")}</ul>

    <h3>Splunk Search Ideas</h3>
    <ul>${(explanation.splunk_search_ideas || []).map(x => `<li><code>${x}</code></li>`).join("")}</ul>
  `;
}

async function analyzeEvent() {
  const predictionBox = document.getElementById("predictionBox");
  const llmBox = document.getElementById("llmBox");

  predictionBox.innerHTML = "Analyzing...";
  llmBox.innerHTML = "Generating LLM explanation...";

  const payload = {
    EventID: getValue("EventID"),
    Image: getValue("Image"),
    CommandLine: getValue("CommandLine"),
    ParentImage: getValue("ParentImage"),
    ParentCommandLine: getValue("ParentCommandLine"),
    User: getValue("User"),
    Computer: getValue("Computer"),
    DestinationIp: getValue("DestinationIp"),
    DestinationPort: getValue("DestinationPort"),
    TargetFilename: getValue("TargetFilename"),
    TargetObject: getValue("TargetObject")
  };

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error("API error: " + response.status);
    }

    const data = await response.json();

    const pred = data.ml_prediction;

    predictionBox.className = "prediction";
    predictionBox.innerHTML = `
      <div class="big">${pred.final_label}</div>
      <div>Level: <strong>${pred.final_level}</strong></div>
      <div>Confidence: <strong>${percent(pred.confidence)}</strong></div>
      <div>Confidence Level: <strong>${pred.confidence_level}</strong></div>
      <p>${pred.decision_reason}</p>
    `;

    renderTopK("parentTop", pred.parent_top3 || []);
    renderTopK("subTop", pred.subtechnique_top5 || []);
    renderLLM(data.llm_explanation);

    document.getElementById("eventText").innerText = data.event_text;

  } catch (err) {
    predictionBox.innerHTML = "Error: " + err.message;
    llmBox.innerHTML = "Failed to generate explanation.";
  }
}

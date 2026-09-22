const SAMPLES = {
  bank: "URGENT: Your Chase account has been locked due to suspicious activity. Verify identity within 15 minutes or funds will be seized. Click: https://chase-secure-login.help-verify.ru/session?id=8821\nFrom: security@chase-alerts.co",
  invoice: "Hi, updated wiring instructions for Invoice #4419 (Acme Supplies). Please send $18450 today to new remit email billing@acme-supplies-pay.com before 4pm or shipment holds.",
  crypto: "Hey this is MetaMask support. Unauthorized access detected. Connect your wallet and enter your 12-word phrase: https://metamask-support-help.web.app/restore"
};
function householdId() {
  const key = "scamshield.household";
  let id = localStorage.getItem(key);
  if (!id) { id = crypto.randomUUID(); localStorage.setItem(key, id); }
  return id;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function render(result) {
  const el = document.getElementById("result");
  el.style.display = "block";
  const tags = (result.indicators || []).length
    ? `<div class="indicators">${result.indicators.map((i) => `<span class="tag">${escapeHtml(i.kind)} ${escapeHtml(i.value)}</span>`).join("")}</div>`
    : `<p class="hint">No structured identifiers extracted.</p>`;
  const intel = (result.intel || []).map((i) => `<li>${escapeHtml(i.provider)} · ${escapeHtml(i.status)} · ${escapeHtml(i.summary)}</li>`).join("");
  el.innerHTML = `
    <div class="verdict ${escapeHtml(result.verdict)}">
      <div class="badge">${escapeHtml(result.verdict)}</div>
      <div>score ${escapeHtml(String(result.score))}/100 · links not opened · ${escapeHtml(result.check_id.slice(0, 8))}</div>
    </div>
    <div class="section"><h3>Plain English</h3><p>${escapeHtml(result.summary)}</p></div>
    <div class="section"><h3>Extracted indicators</h3>${tags}</div>
    <div class="section"><h3>Evidence</h3><ul class="evidence">${(result.evidence || []).map((e) => `<li><strong>${escapeHtml(e.code)}</strong> · ${escapeHtml(e.detail)}</li>`).join("")}</ul></div>
    <div class="section"><h3>Live intel</h3><ul class="evidence">${intel || "<li>No live providers configured or no URL to check.</li>"}</ul></div>
    <div class="section"><h3>What you should do</h3><div class="actions"><ol>${(result.actions || []).map((a) => `<li>${escapeHtml(a)}</li>`).join("")}</ol></div></div>`;
  el.scrollIntoView({ behavior: "smooth", block: "start" });
}
function saveHistory(verdict, preview) {
  const key = "scamshield.history.v1";
  const items = JSON.parse(localStorage.getItem(key) || "[]");
  items.unshift({ t: new Date().toISOString(), verdict, preview: preview.slice(0, 80) });
  localStorage.setItem(key, JSON.stringify(items.slice(0, 20)));
  drawHistory();
}
function drawHistory() {
  const items = JSON.parse(localStorage.getItem("scamshield.history.v1") || "[]");
  const box = document.getElementById("history");
  if (!items.length) { box.textContent = "No checks yet."; return; }
  box.innerHTML = items.map((i) => `<div class="hist-item"><span>${escapeHtml(i.verdict)} · ${escapeHtml(i.preview)}</span><span>${escapeHtml(i.t.slice(0,16).replace("T"," "))}</span></div>`).join("");
}
function showError(msg) {
  const el = document.getElementById("error");
  el.hidden = !msg;
  el.textContent = msg || "";
}
async function runCheck() {
  const content = document.getElementById("input").value.trim();
  showError("");
  if (!content) { showError("Paste the suspicious content first."); return; }
  const btn = document.getElementById("checkBtn");
  btn.disabled = true;
  document.getElementById("status").textContent = "Checking…";
  try {
    const res = await fetch("/api/check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content, source_hint: "web", household_id: householdId() }) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Check failed");
    render(data);
    saveHistory(data.verdict, content);
  } catch (err) {
    showError(err.message || "Check failed");
  } finally {
    btn.disabled = false;
    document.getElementById("status").textContent = "";
  }
}
document.getElementById("checkBtn").addEventListener("click", runCheck);
document.getElementById("clearBtn").addEventListener("click", () => {
  document.getElementById("input").value = "";
  document.getElementById("result").style.display = "none";
  showError("");
});
document.querySelectorAll("[data-sample]").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.getElementById("input").value = SAMPLES[btn.dataset.sample];
    runCheck();
  });
});
document.getElementById("file").addEventListener("change", async (ev) => {
  const file = ev.target.files && ev.target.files[0];
  if (!file) return;
  showError("");
  document.getElementById("status").textContent = "Uploading…";
  const body = new FormData();
  body.append("file", file);
  body.append("household_id", householdId());
  try {
    const res = await fetch("/api/check-upload", { method: "POST", body });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Upload check failed");
    render(data);
    saveHistory(data.verdict, file.name);
  } catch (err) {
    showError(err.message || "Upload failed");
  } finally {
    document.getElementById("status").textContent = "";
    ev.target.value = "";
  }
});
drawHistory();

(function () {
  "use strict";
  const { el, clear, badge } = PP;
  const form = document.getElementById("sim-form");
  const $ = (id) => document.getElementById(id);
  let cat = null;

  function fillSelect(sel, items, labeler) {
    clear(sel);
    items.forEach((i) => sel.append(el("option", { value: i.value || i, text: labeler ? labeler(i) : i })));
  }

  function permHint() {
    const res = cat.resources.find((r) => r.id === $("resource_id").value);
    if (!res) return;
    const allowed = res.permissions[$("role").value] || [];
    $("perm-hint").textContent = res.name + " (" + res.sensitivity + " sensitivity): role '" + $("role").value +
      "' is granted " + (allowed.length ? allowed.join(", ") : "no actions") + ".";
  }

  function setForm(r) {
    $("user_id").value = r.user_id; $("role").value = r.role; $("resource_id").value = r.resource_id;
    $("action").value = r.action; $("device_trust").value = r.device_trust;
    $("access_context").value = r.access_context; $("failed_logins").value = r.failed_logins;
    $("mfa_verified").checked = r.mfa_verified; permHint();
  }

  function readForm() {
    const failed = Number($("failed_logins").value);
    return {
      user_id: $("user_id").value.trim(), role: $("role").value, resource_id: $("resource_id").value,
      action: $("action").value, device_trust: $("device_trust").value, access_context: $("access_context").value,
      mfa_verified: $("mfa_verified").checked,
      failed_logins: Number.isInteger(failed) ? failed : -1,
    };
  }

  function renderResult(r) {
    $("result").className = "card verdict " + r.decision;
    $("result-empty").classList.add("hidden");
    const body = clear($("result-body"));
    body.classList.remove("hidden");
    const rules = r.matched_rules.map((m) => el("div", { class: "rule" + (m.decisive ? " decisive" : "") },
      el("code", { text: m.code }), el("span", { text: m.name }), badge(m.effect),
      m.mandatory ? badge("mandatory", "mand") : null,
      m.decisive ? el("span", { class: "muted", text: "decisive" }) : null));
    const factors = r.risk_factors.filter((f) => f.points > 0).map((f) =>
      el("li", { text: f.factor.replace("_", " ") + " = " + f.value + ": +" + f.points }));
    body.append(
      el("div", { class: "verdict-head" }, el("span", { class: "verdict-word", text: r.decision.replace("_", " ") }),
        el("span", { class: "badge neutral", text: "Risk " + r.risk_score + "/100 (" + r.risk_level + ")" })),
      el("div", { class: "meter", role: "img", "aria-label": "Risk meter " + r.risk_score + " of 100" },
        el("div", { class: "meter-fill", id: "meter-fill" }),
        el("div", { class: "meter-ticks" },
          [["0", 0], ["30", 30], ["60", 60], ["80", 80], ["100", 100]].map(([t, p]) => {
            const s = el("span", { text: t }); s.style.left = p + "%"; return s; }))),
      el("h3", { text: "Why" }), el("p", { text: r.explanation }),
      el("h3", { text: "Recommended remediation" }), el("ul", { class: "plain" }, r.remediation.map((t) => el("li", { text: t }))),
      el("h3", { text: "Matched rules" }), rules,
      el("details", {}, el("summary", { text: "Risk score breakdown" }),
        factors.length ? el("ul", { class: "plain" }, factors) : el("p", { class: "muted", text: "No risk points were added." })),
      el("p", { class: "muted", text: "Event " + r.request_id + " at " + new Date(r.timestamp).toLocaleString() }));
    $("meter-fill").style.left = "calc(" + r.risk_score + "% - 2px)";
  }

  async function submit(ev) {
    ev.preventDefault();
    const payload = readForm();
    if (!/^[A-Za-z0-9_.@-]{1,64}$/.test(payload.user_id)) { PP.toast("Identity may contain only letters, digits and . _ @ -", true); return; }
    if (payload.failed_logins < 0 || payload.failed_logins > 100) { PP.toast("Failed logins must be a whole number from 0 to 100", true); return; }
    const btn = $("submit-btn"); btn.disabled = true;
    try { renderResult(await PP.api("/api/evaluate", { method: "POST", body: JSON.stringify(payload) })); }
    catch (e) { PP.toast(e.message, true); }
    finally { btn.disabled = false; }
  }

  Promise.all([PP.catalog(), PP.api("/api/scenarios")]).then(([c, scenarios]) => {
    cat = c;
    fillSelect($("role"), c.roles);
    fillSelect($("resource_id"), c.resources.map((r) => ({ value: r.id, name: r.name, s: r.sensitivity })), (r) => r.name + " [" + r.s + "]");
    fillSelect($("action"), c.actions);
    fillSelect($("device_trust"), c.device_trust);
    fillSelect($("access_context"), c.access_contexts);
    c.identities.forEach((i) => $("identities").append(el("option", { value: i.user_id, label: i.label })));
    const box = $("scenarios");
    scenarios.forEach((s, idx) => box.append(el("button", { type: "button", class: "btn secondary", title: s.description,
      onclick: () => { setForm(s.request); form.requestSubmit(); } }, (idx + 1) + ". " + s.title)));
    setForm(scenarios[0].request);
  }).catch((e) => PP.toast(e.message, true));

  ["role", "resource_id"].forEach((id) => $(id).addEventListener("change", () => cat && permHint()));
  $("user_id").addEventListener("change", () => {
    const hit = cat && cat.identities.find((i) => i.user_id === $("user_id").value);
    if (hit) { $("role").value = hit.role; permHint(); }
  });
  form.addEventListener("submit", submit);
})();

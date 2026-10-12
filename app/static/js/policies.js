(function () {
  "use strict";
  const { el, clear, badge, emptyRow } = PP;
  const $ = (id) => document.getElementById(id);
  let cat = null;
  let editing = null; // policy object being edited, or null for create

  function condText(c) {
    const ops = { eq: "=", neq: "!=", gt: ">", gte: ">=", lt: "<", lte: "<=", in: "in", not_in: "not in" };
    const v = Array.isArray(c.value) ? "[" + c.value.join(", ") + "]" : String(c.value);
    return c.field + " " + (ops[c.operator] || c.operator) + " " + v;
  }

  async function load() {
    try {
      const policies = await PP.api("/api/policies");
      const body = clear($("policy-body"));
      if (!policies.length) body.append(emptyRow(7, "No policies defined."));
      policies.forEach((p) => body.append(el("tr", {},
        el("td", {}, el("code", { text: p.code })),
        el("td", {}, el("strong", { text: p.name }), el("div", { class: "muted", text: p.description })),
        el("td", {}, el("ul", { class: "cond-list" }, p.conditions.map((c) => el("li", { text: condText(c) })))),
        el("td", {}, badge(p.effect)),
        el("td", { class: "num", text: p.priority }),
        el("td", {}, badge(p.enabled ? "enabled" : "disabled", p.enabled ? "on" : "off"), " ",
          p.mandatory ? badge("mandatory", "mand") : null),
        el("td", {}, el("button", { class: "btn secondary small", type: "button", onclick: () => openDialog(p) }, "Edit"), " ",
          p.mandatory ? null : el("button", { class: "btn secondary small", type: "button", onclick: () => toggle(p) }, p.enabled ? "Disable" : "Enable"), " ",
          p.mandatory ? null : el("button", { class: "btn danger small", type: "button", onclick: () => remove(p) }, "Delete")))));
    } catch (e) { PP.toast(e.message, true); }
  }

  async function toggle(p) {
    try {
      await PP.api("/api/policies/" + p.id, { method: "PATCH", body: JSON.stringify({ enabled: !p.enabled }) });
      PP.toast("Policy " + p.code + (p.enabled ? " disabled" : " enabled")); load();
    } catch (e) { PP.toast(e.message, true); }
  }

  async function remove(p) {
    if (!confirm("Delete policy " + p.code + " (" + p.name + ")?")) return;
    try { await PP.api("/api/policies/" + p.id, { method: "DELETE" }); PP.toast("Policy deleted"); load(); }
    catch (e) { PP.toast(e.message, true); }
  }

  // ---- condition editor -------------------------------------------------
  function valueControl(field, op, value) {
    const spec = cat.policy_fields[field];
    if (spec.type === "bool") {
      const s = el("select", { "aria-label": "Condition value" }, el("option", { value: "true", text: "true" }), el("option", { value: "false", text: "false" }));
      s.value = String(value === undefined ? true : value); return s;
    }
    if (spec.type === "int") {
      return el("input", { type: "number", min: spec.min, max: spec.max, step: 1, value: value === undefined ? spec.min : value, "aria-label": "Condition value" });
    }
    const multi = op === "in" || op === "not_in";
    const s = el("select", { "aria-label": "Condition value", multiple: multi ? true : null, size: multi ? 4 : null },
      spec.values.map((v) => el("option", { value: v, text: v })));
    const wanted = multi ? (Array.isArray(value) ? value : []) : [value === undefined ? spec.values[0] : value];
    Array.from(s.options).forEach((o) => { o.selected = wanted.includes(o.value); });
    return s;
  }

  function opsFor(field) {
    const t = cat.policy_fields[field].type;
    return t === "int" ? ["eq", "neq", "gt", "gte", "lt", "lte"] : t === "bool" ? ["eq", "neq"] : ["eq", "neq", "in", "not_in"];
  }

  function addCondition(c, locked) {
    const row = el("div", { class: "cond-row" });
    const field = el("select", { "aria-label": "Condition field", disabled: locked ? true : null },
      Object.keys(cat.policy_fields).map((f) => el("option", { value: f, text: f })));
    const op = el("select", { "aria-label": "Condition operator", disabled: locked ? true : null });
    const holder = el("div");
    const rebuild = (keepOp, keepVal) => {
      clear(op); opsFor(field.value).forEach((o) => op.append(el("option", { value: o, text: o })));
      if (keepOp && opsFor(field.value).includes(keepOp)) op.value = keepOp;
      clear(holder); const ctl = valueControl(field.value, op.value, keepVal);
      if (locked) ctl.disabled = true; holder.append(ctl);
    };
    field.value = c ? c.field : "risk_score"; rebuild(c && c.operator, c && c.value);
    field.addEventListener("change", () => rebuild());
    op.addEventListener("change", () => rebuild(op.value));
    row.append(field, op, holder, locked ? el("span") : el("button", { type: "button", class: "btn secondary small", onclick: () => row.remove() }, "Remove"));
    row._get = () => {
      const spec = cat.policy_fields[field.value]; const ctl = holder.firstChild; let value;
      if (spec.type === "bool") value = ctl.value === "true";
      else if (spec.type === "int") value = ctl.value === "" ? null : Number(ctl.value);
      else if (ctl.multiple) value = Array.from(ctl.selectedOptions).map((o) => o.value);
      else value = ctl.value;
      return { field: field.value, operator: op.value, value };
    };
    $("cond-rows").append(row);
  }

  function openDialog(policy) {
    editing = policy || null;
    const locked = !!(policy && policy.mandatory);
    $("dlg-title").textContent = policy ? "Edit " + policy.code : "New policy";
    $("p-name").value = policy ? policy.name : ""; $("p-desc").value = policy ? policy.description : "";
    $("p-priority").value = policy ? policy.priority : 300; $("p-remed").value = policy ? policy.remediation : "";
    $("p-enabled").checked = policy ? policy.enabled : true;
    fillEffects(policy ? policy.effect : "STEP_UP");
    clear($("cond-rows"));
    (policy ? policy.conditions : [{ field: "risk_score", operator: "gte", value: 60 }]).forEach((c) => addCondition(c, locked));
    ["p-name", "p-priority", "p-effect", "p-enabled"].forEach((id) => { $(id).disabled = locked; });
    $("add-cond").classList.toggle("hidden", locked);
    $("mand-note").classList.toggle("hidden", !locked);
    $("dlg-error").textContent = "";
    $("policy-dialog").showModal();
  }

  function fillEffects(selected) {
    const s = clear($("p-effect")); cat.policy_effects.forEach((e) => s.append(el("option", { value: e, text: e }))); s.value = selected;
  }

  async function save(ev) {
    ev.preventDefault();
    const conds = Array.from($("cond-rows").children).map((r) => r._get());
    const body = { description: $("p-desc").value.trim(), remediation: $("p-remed").value.trim() };
    if (!(editing && editing.mandatory)) {
      Object.assign(body, { name: $("p-name").value.trim(), effect: $("p-effect").value, conditions: conds,
        priority: Number($("p-priority").value), enabled: $("p-enabled").checked });
    }
    try {
      if (editing) await PP.api("/api/policies/" + editing.id, { method: "PATCH", body: JSON.stringify(body) });
      else await PP.api("/api/policies", { method: "POST", body: JSON.stringify(body) });
      $("policy-dialog").close(); PP.toast("Policy saved"); load();
    } catch (e) { $("dlg-error").textContent = e.message; }
  }

  PP.catalog().then((c) => {
    cat = c; load();
    $("new-policy").addEventListener("click", () => openDialog(null));
    $("add-cond").addEventListener("click", () => addCondition(null, false));
    $("dlg-cancel").addEventListener("click", () => $("policy-dialog").close());
    $("policy-form").addEventListener("submit", save);
  }).catch((e) => PP.toast(e.message, true));
})();

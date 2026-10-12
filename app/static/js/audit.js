(function () {
  "use strict";
  const { el, clear, badge, time, emptyRow } = PP;
  const $ = (id) => document.getElementById(id);
  const PAGE_SIZE = 15;
  let page = 1, pages = 1;

  function params(extra) {
    const p = new URLSearchParams();
    const map = { q: "f-q", decision: "f-decision", user_id: "f-user", resource_id: "f-resource", min_risk: "f-min", max_risk: "f-max" };
    Object.entries(map).forEach(([k, id]) => { const v = $(id).value.trim(); if (v !== "") p.set(k, v); });
    Object.entries(extra || {}).forEach(([k, v]) => p.set(k, v));
    return p;
  }

  function detailRow(r) {
    const md = r.event_metadata || {};
    return el("tr", { class: "detail hidden" }, el("td", { colspan: 9 },
      el("p", {}, el("strong", { text: "Explanation: " }), r.explanation),
      el("p", {}, el("strong", { text: "Remediation: " }), (r.remediation || []).join(" ")),
      el("p", { class: "mono", text: "device=" + md.device_trust + " mfa=" + md.mfa_verified + " failed_logins=" + md.failed_logins +
        " context=" + md.access_context + " sensitivity=" + md.resource_sensitivity + " engine=" + md.engine_version }),
      el("p", { class: "mono", text: "Event ID: " + r.event_id })));
  }

  async function load() {
    try {
      const d = await PP.api("/api/audit-logs?" + params({ page, page_size: PAGE_SIZE }));
      pages = d.pages;
      const body = clear($("audit-body"));
      if (!d.items.length) body.append(emptyRow(9, "No audit events match these filters."));
      d.items.forEach((r) => {
        const detail = detailRow(r);
        const btn = el("button", { class: "btn secondary small", type: "button", "aria-expanded": "false", onclick: () => {
          const open = detail.classList.toggle("hidden") === false; btn.setAttribute("aria-expanded", String(open)); } }, "Details");
        body.append(el("tr", {},
          el("td", { text: time(r.timestamp) }), el("td", {}, el("code", { text: r.event_id.slice(0, 8) })),
          el("td", { text: r.user_id }), el("td", { text: r.resource_id }), el("td", { text: r.action }),
          el("td", {}, badge(r.decision)), el("td", { class: "num", text: r.risk_score }),
          el("td", { class: "mono", text: r.matched_rules.map((m) => m.code).join(", ") }), el("td", {}, btn)), detail);
      });
      $("page-info").textContent = d.total + " event(s). Page " + d.page + " of " + d.pages + ".";
      $("prev").disabled = d.page <= 1; $("next").disabled = d.page >= d.pages;
      $("export-link").href = "/api/audit-logs/export?" + params();
    } catch (e) { PP.toast(e.message, true); }
  }

  $("filters").addEventListener("submit", (e) => { e.preventDefault(); page = 1; load(); });
  $("f-reset").addEventListener("click", () => { $("filters").reset(); page = 1; load(); });
  $("prev").addEventListener("click", () => { if (page > 1) { page--; load(); } });
  $("next").addEventListener("click", () => { if (page < pages) { page++; load(); } });
  PP.catalog().then((c) => {
    c.resources.forEach((r) => $("f-resource").append(el("option", { value: r.id, text: r.id })));
  }).catch(() => {}).finally(load);
})();

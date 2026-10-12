(function () {
  "use strict";
  const { el, clear, badge, time, emptyRow } = PP;
  const COLORS = { ALLOW: "#0b6e4f", DENY: "#b3261e", STEP_UP: "#b8741a" };
  const charts = {};

  function draw(id, config) {
    if (charts[id]) charts[id].destroy();
    charts[id] = new Chart(document.getElementById(id), config);
  }

  function render(d) {
    document.getElementById("k-total").textContent = d.total_requests;
    document.getElementById("k-allow").textContent = d.allowed;
    document.getElementById("k-deny").textContent = d.denied;
    document.getElementById("k-step").textContent = d.step_up;

    const common = { responsive: true, maintainAspectRatio: false, animation: false };
    draw("chart-timeline", {
      type: "bar",
      data: {
        labels: d.timeline.map((t) => t.date.slice(5)),
        datasets: ["ALLOW", "STEP_UP", "DENY"].map((k) => ({
          label: k.replace("_", " "), data: d.timeline.map((t) => t[k]), backgroundColor: COLORS[k],
        })),
      },
      options: Object.assign({}, common, {
        scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } },
      }),
    });
    draw("chart-mix", {
      type: "doughnut",
      data: { labels: ["Allow", "Step up", "Deny"],
        datasets: [{ data: [d.allowed, d.step_up, d.denied], backgroundColor: [COLORS.ALLOW, COLORS.STEP_UP, COLORS.DENY] }] },
      options: Object.assign({}, common, { plugins: { legend: { position: "bottom" } } }),
    });
    draw("chart-risk", {
      type: "bar",
      data: { labels: d.risk_distribution.map((b) => b.label),
        datasets: [{ label: "Requests", data: d.risk_distribution.map((b) => b.count), backgroundColor: "#0a5fb4" }] },
      options: Object.assign({}, common, { plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { title: { display: true, text: "Risk score" } } } }),
    });

    const act = clear(document.getElementById("activity-body"));
    document.getElementById("activity-note").textContent =
      "Rule matches across the latest " + d.activity_window + " evaluation(s).";
    if (!d.policy_activity.length) act.append(emptyRow(3, "No evaluations yet."));
    d.policy_activity.forEach((p) => act.append(el("tr", {},
      el("td", {}, el("code", { text: p.code })), el("td", { text: p.name }), el("td", { class: "num", text: p.hits }))));

    const body = clear(document.getElementById("recent-body"));
    if (!d.recent_decisions.length) body.append(emptyRow(6, "No decisions yet. Run a scenario in the simulator."));
    d.recent_decisions.forEach((r) => body.append(el("tr", {},
      el("td", { text: time(r.timestamp) }), el("td", { text: r.user_id }), el("td", { text: r.resource_id }),
      el("td", { text: r.action }), el("td", {}, badge(r.decision)), el("td", { class: "num", text: r.risk_score }))));
  }

  PP.api("/api/dashboard").then(render).catch((e) => PP.toast(e.message, true));
})();

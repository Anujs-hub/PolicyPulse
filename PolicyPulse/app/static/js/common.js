/* Shared helpers. All dynamic content is inserted with textContent (no innerHTML) to avoid XSS. */
(function () {
  "use strict";
  const PP = (window.PP = {});

  PP.el = function (tag, attrs, ...kids) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? "" : String(v));
    }
    for (const kid of kids.flat()) {
      if (kid === null || kid === undefined || kid === false) continue;
      node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return node;
  };

  PP.clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); return node; };

  PP.errorText = function (data, status) {
    if (data && typeof data.detail === "string") return data.detail;
    if (data && Array.isArray(data.detail)) {
      return data.detail.map((e) => {
        const loc = (e.loc || []).filter((p) => p !== "body").join(".");
        return (loc ? loc + ": " : "") + e.msg;
      }).join("\n");
    }
    return "Request failed (HTTP " + status + ")";
  };

  PP.api = async function (path, options) {
    const opts = Object.assign({ headers: { "Content-Type": "application/json" } }, options || {});
    let res;
    try { res = await fetch(path, opts); }
    catch (e) { throw new Error("Cannot reach the PolicyPulse server. Is it running?"); }
    if (res.status === 204) return null;
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON body */ }
    if (!res.ok) throw new Error(PP.errorText(data, res.status));
    return data;
  };

  let catalogPromise = null;
  PP.catalog = () => (catalogPromise = catalogPromise || PP.api("/api/catalog"));

  PP.badge = (text, cls) => PP.el("span", { class: "badge " + (cls || text), text: String(text).replace("_", " ") });
  PP.time = (iso) => { const d = new Date(iso); return isNaN(d) ? String(iso) : d.toLocaleString(); };

  let toastTimer = null;
  PP.toast = function (message, isError) {
    const old = document.querySelector(".toast");
    if (old) old.remove();
    const t = PP.el("div", { class: "toast" + (isError ? " error" : ""), role: isError ? "alert" : "status", text: message });
    document.body.append(t);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.remove(), 5000);
  };

  PP.emptyRow = (cols, text) => PP.el("tr", {}, PP.el("td", { colspan: cols, class: "empty", text }));

  document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("nav-toggle");
    const side = document.getElementById("sidenav");
    if (btn && side) {
      btn.addEventListener("click", () => {
        const open = side.classList.toggle("open");
        btn.setAttribute("aria-expanded", String(open));
      });
    }
  });
})();

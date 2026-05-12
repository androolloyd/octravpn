// OctraVPN admin UI — vanilla JS, no build step.

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

async function api(path, opts = {}) {
  const r = await fetch("/api" + path, {
    headers: { "content-type": "application/json" },
    ...opts,
  });
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new Error(body.error || `HTTP ${r.status}`);
  }
  return r.json();
}

function el(tag, attrs = {}, children = []) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "onclick") e.addEventListener("click", v);
    else if (k === "html") e.innerHTML = v;
    else if (v !== undefined && v !== null) e.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (typeof c === "string") e.append(c);
    else if (c) e.append(c);
  }
  return e;
}

function shorten(s, n = 10) {
  if (!s) return "";
  if (s.length <= n + 4) return s;
  return s.slice(0, n) + "…" + s.slice(-4);
}

// ---------------- nav ----------------

function setView(name) {
  $$(".view").forEach((v) => v.classList.add("hidden"));
  const el = document.getElementById("view-" + name);
  if (el) el.classList.remove("hidden");
  $$("nav a").forEach((a) => a.classList.toggle("active", a.hash === "#" + name));
}

window.addEventListener("hashchange", () => {
  const name = location.hash.replace("#", "") || "tailnets";
  setView(name);
});

// ---------------- tailnets ----------------

let writable = false;

async function loadTailnets() {
  const tbody = $("#tailnet-table tbody");
  tbody.innerHTML = "";
  let ids;
  try {
    ids = await api("/tailnets");
  } catch (e) {
    tbody.append(el("tr", {}, el("td", { colspan: "6" }, "error: " + e.message)));
    return;
  }
  if (!ids || ids.length === 0) {
    tbody.append(el("tr", {}, el("td", { colspan: "6" }, "no tailnets")));
    return;
  }
  for (const id of ids) {
    let t = null;
    try {
      t = await api("/tailnets/" + id);
    } catch (_) {}
    if (!t) continue;
    const row = el("tr", {}, [
      el("td", {}, el("code", {}, shorten(id, 12))),
      el("td", {}, el("code", {}, shorten(t.owner))),
      el("td", {}, String(t.member_count ?? 0)),
      el("td", {}, String(t.treasury ?? 0)),
      el("td", {}, String(t.exit_count ?? 0)),
      el(
        "td",
        {},
        el(
          "button",
          {
            class: "ghost",
            onclick: () => toggleExpand(row, id),
          },
          "details"
        )
      ),
    ]);
    tbody.append(row);
  }
}

function toggleExpand(row, id) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains("expand-row")) {
    next.remove();
    return;
  }
  const td = el("td", { colspan: "6" }, buildExpand(id));
  const expandRow = el("tr", { class: "expand-row" }, td);
  row.after(expandRow);
}

function buildExpand(id) {
  const memberAddr = el("input", { type: "text", placeholder: "octADDR…" });
  const addBtn = el(
    "button",
    {
      class: "primary",
      onclick: async () => {
        if (!writable) return alert("read-only: no wallet bound");
        try {
          await api("/tailnets/" + id + "/members", {
            method: "POST",
            body: JSON.stringify({ addr: memberAddr.value.trim() }),
          });
          alert("member added");
          loadTailnets();
        } catch (e) {
          alert(e.message);
        }
      },
    },
    "add member"
  );
  const removeAddr = el("input", { type: "text", placeholder: "octADDR…" });
  const removeBtn = el(
    "button",
    {
      class: "danger",
      onclick: async () => {
        if (!writable) return alert("read-only: no wallet bound");
        try {
          await api(
            "/tailnets/" + id + "/members/" + encodeURIComponent(removeAddr.value.trim()),
            { method: "DELETE" }
          );
          alert("removed");
          loadTailnets();
        } catch (e) {
          alert(e.message);
        }
      },
    },
    "remove"
  );
  const topupAmount = el("input", { type: "number", placeholder: "OU amount" });
  const topupBtn = el(
    "button",
    {
      class: "primary",
      onclick: async () => {
        if (!writable) return alert("read-only");
        try {
          await api("/tailnets/" + id + "/deposit", {
            method: "POST",
            body: JSON.stringify({ amount: parseInt(topupAmount.value, 10) }),
          });
          alert("treasury topped up");
          loadTailnets();
        } catch (e) {
          alert(e.message);
        }
      },
    },
    "top up"
  );
  const exitAddr = el("input", { type: "text", placeholder: "octVALIDATOR…" });
  const exitBtn = el(
    "button",
    {
      class: "primary",
      onclick: async () => {
        if (!writable) return alert("read-only");
        try {
          await api("/tailnets/" + id + "/exits", {
            method: "POST",
            body: JSON.stringify({ validator: exitAddr.value.trim() }),
          });
          alert("exit configured");
          loadTailnets();
        } catch (e) {
          alert(e.message);
        }
      },
    },
    "configure"
  );
  return el("div", { class: "expand" }, [
    el("div", { class: "row" }, [
      el("strong", {}, "id"),
      el("code", { class: "mono" }, id),
    ]),
    el("div", { class: "row" }, [memberAddr, addBtn, removeAddr, removeBtn]),
    el("div", { class: "row" }, [topupAmount, topupBtn]),
    el("div", { class: "row" }, [exitAddr, exitBtn]),
  ]);
}

// ---------------- endpoints ----------------

async function loadEndpoints() {
  const tbody = $("#endpoint-table tbody");
  tbody.innerHTML = "";
  let addrs;
  try {
    addrs = await api("/endpoints");
  } catch (e) {
    tbody.append(el("tr", {}, el("td", { colspan: "5" }, "error: " + e.message)));
    return;
  }
  if (!addrs || addrs.length === 0) {
    tbody.append(el("tr", {}, el("td", { colspan: "5" }, "no endpoints")));
    return;
  }
  for (const a of addrs) {
    let ep = null;
    try {
      ep = await api("/endpoints/" + a);
    } catch (_) {}
    if (!ep) continue;
    tbody.append(
      el("tr", {}, [
        el("td", {}, el("code", {}, shorten(a))),
        el("td", {}, ep.region || ""),
        el("td", {}, ep.endpoint || ""),
        el("td", {}, String(ep.price_per_mb || 0)),
        el("td", {}, String(ep.reputation || 0)),
      ])
    );
  }
}

// ---------------- ACL editor ----------------

async function computeAclHash() {
  try {
    const r = await api("/acl/hash", {
      method: "POST",
      body: JSON.stringify({ doc: $("#acl-doc").value }),
    });
    $("#acl-hash-out").textContent = r.hash;
  } catch (e) {
    $("#acl-hash-out").textContent = "error: " + e.message;
  }
}

// ---------------- bootstrap ----------------

async function loadIdentity() {
  let r;
  try {
    r = await api("/identity");
  } catch (e) {
    $("#env-badge").textContent = "rpc unreachable";
    return;
  }
  writable = !!r.writable;
  const badge = $("#env-badge");
  if (writable) {
    badge.textContent = "writable: " + shorten(r.caller);
    badge.classList.add("writable");
  } else {
    badge.textContent = "read-only";
    badge.classList.add("readonly");
  }
  $("#about-program").textContent = r.program;
  $("#about-signer").textContent = r.caller || "(none)";
}

async function loadVersion() {
  try {
    const r = await api("/version");
    $("#about-version").textContent = r.version;
  } catch (_) {}
}

function bindButtons() {
  $("#btn-refresh-tailnets").addEventListener("click", loadTailnets);
  $("#btn-refresh-endpoints").addEventListener("click", loadEndpoints);
  $("#btn-acl-hash").addEventListener("click", computeAclHash);
}

window.addEventListener("DOMContentLoaded", async () => {
  bindButtons();
  setView(location.hash.replace("#", "") || "tailnets");
  await Promise.all([loadIdentity(), loadVersion()]);
  await loadTailnets();
  await loadEndpoints();
  // Sample ACL doc for the editor.
  $("#acl-doc").value =
    'version = 1\n\n[groups]\nadmins = ["octADMIN..."]\n\n[[rules]]\naction = "accept"\nsrc = ["group:admins"]\ndst = ["*"]\n';
});

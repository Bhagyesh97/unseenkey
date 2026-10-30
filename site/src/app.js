// unseenkey.com page script. Bundled with anime.js by `npm run build`.
// Everything here is progressive enhancement: the page reads fine without it.
import { animate, createTimeline, stagger } from "animejs";

const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));

/* ---------- theme ---------- */
(function theme() {
  const root = document.documentElement;
  const btn = $("#theme");
  const order = ["system", "light", "dark"];
  let mode = "system";
  try {
    mode = localStorage.getItem("theme") || "system";
  } catch {}
  const apply = () => {
    if (mode === "system") delete root.dataset.theme;
    else root.dataset.theme = mode;
    if (btn) btn.setAttribute("aria-label", `Theme: ${mode}. Click to change.`);
    if (btn) btn.dataset.mode = mode;
  };
  apply();
  btn?.addEventListener("click", () => {
    mode = order[(order.indexOf(mode) + 1) % order.length];
    try {
      localStorage.setItem("theme", mode);
    } catch {}
    apply();
  });
})();

/* ---------- cursor glow on the hero ---------- */
(function glow() {
  const hero = $(".hero");
  if (!hero || reduced || matchMedia("(pointer: coarse)").matches) return;
  hero.addEventListener("pointermove", (e) => {
    const r = hero.getBoundingClientRect();
    hero.style.setProperty("--mx", `${((e.clientX - r.left) / r.width) * 100}%`);
    hero.style.setProperty("--my", `${((e.clientY - r.top) / r.height) * 100}%`);
  }, { passive: true });
})();

/* ---------- 3D hero, or the still ---------- */
(function hero3d() {
  const canvas = $("#hero-canvas");
  const still = $("#hero-still");
  if (!canvas) return;
  const wide = matchMedia("(min-width: 900px)").matches;
  const test = document.createElement("canvas");
  const webgl = !!(test.getContext("webgl2") || test.getContext("webgl"));
  if (!wide || reduced || !webgl || new URLSearchParams(location.search).has("still")) return;
  const accent = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim() || "#0969da";
  import("/hero3d.js")
    .then((m) => {
      const handle = m.mountHero(canvas, { accent });
      window.__hero = handle;
      canvas.classList.add("on");
      if (still) still.classList.add("off");
    })
    .catch(() => {});
})();

/* ---------- reveals, staggered grids, counters ---------- */
(function reveals() {
  const items = $$("[data-reveal]");
  if (!("IntersectionObserver" in window) || reduced) {
    items.forEach((el) => el.classList.add("in"));
    $$("[data-count]").forEach((el) => (el.textContent = el.dataset.count));
    return;
  }
  const io = new IntersectionObserver((entries) => {
    for (const en of entries) {
      if (!en.isIntersecting) continue;
      const el = en.target;
      io.unobserve(el);
      el.classList.add("in");
      const kids = el.dataset.reveal === "stagger" ? Array.from(el.children) : null;
      if (kids && kids.length) {
        try {
          animate(kids, { opacity: [0, 1], y: [18, 0], duration: 650, ease: "outCubic", delay: stagger(70) });
        } catch {
          kids.forEach((k) => (k.style.opacity = 1));
        }
      }
    }
  }, { rootMargin: "0px 0px -10% 0px" });
  items.forEach((el) => io.observe(el));

  const counters = $$("[data-count]");
  const cio = new IntersectionObserver((entries) => {
    for (const en of entries) {
      if (!en.isIntersecting) continue;
      cio.unobserve(en.target);
      const el = en.target;
      const target = parseFloat(el.dataset.count);
      const decimals = (el.dataset.count.split(".")[1] || "").length;
      const t0 = performance.now();
      const dur = 1300;
      const tick = (now) => {
        const u = Math.min(1, (now - t0) / dur);
        const e = 1 - Math.pow(1 - u, 3);
        el.textContent = (target * e).toFixed(decimals);
        if (u < 1) requestAnimationFrame(tick);
        else el.textContent = el.dataset.count;
      };
      requestAnimationFrame(tick);
    }
  }, { threshold: 0.6 });
  counters.forEach((el) => cio.observe(el));
})();

/* ---------- the terminal that types itself ---------- */
(function terminal() {
  const box = $("#term");
  if (!box) return;
  const script = [
    { cmd: "usk init", out: ["Vault created at %APPDATA%\\Unseenkey\\vault.db", "RECOVERY PHRASE (write it down, shown once):", "  1. ••••••   2. ••••••   3. ••••••   …  24. ••••••"] },
    { cmd: "usk add anthropic", out: ["Value (hidden): ", "Detected: Anthropic", "Upstream locked to: api.anthropic.com", "Tested: works."] },
    { cmd: "usk env anthropic --policy chat", out: ['$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:7391/p/anthropic"', '$env:ANTHROPIC_API_KEY = "<h>usk_h_7Qx9mKpL2vRtWbN4cJ8sYdF3gH6zA1eU</h>"'] },
    { cmd: 'claude -p "hello"', out: ["Hello! How can I help you today?"] },
    { cmd: "usk log", out: ["#14  use   POST api.anthropic.com/v1/messages → 200   anthropic via \"anthropic env\"   1.9 ms", "#13  handle_created   anthropic env   chat", "chain ok (14 events)"] },
  ];
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/&lt;h&gt;/g, '<span class="h">').replace(/&lt;\/h&gt;/g, "</span>");
  const full = (cur) => script.map((l) => `<div class="t-cmd"><span class="t-ps">$</span> ${esc(l.cmd)}${cur ? '<span class="t-cur"></span>' : ""}</div>` + l.out.map((o) => `<div class="t-out">${esc(o)}</div>`).join("")).join("");
  const renderAll = () => {
    box.innerHTML = full(false);
  };
  if (reduced) return renderAll();
  // Reserve the finished session's height up front, so typing it out (and
  // starting over) never moves the rest of the page.
  const reserve = () => {
    const ghost = box.cloneNode(false);
    ghost.removeAttribute("id");
    ghost.removeAttribute("aria-label");
    ghost.style.cssText = `position:absolute;visibility:hidden;left:-9999px;top:0;min-height:0;width:${box.offsetWidth}px`;
    ghost.innerHTML = full(true);
    box.parentNode.appendChild(ghost);
    box.style.minHeight = `${ghost.offsetHeight}px`;
    ghost.remove();
  };
  reserve();
  let resizeTimer;
  addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(reserve, 150);
  }, { passive: true });
  let running = false;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  async function run() {
    if (running) return;
    running = true;
    while (true) {
      box.innerHTML = "";
      for (const line of script) {
        const cmd = document.createElement("div");
        cmd.className = "t-cmd";
        cmd.innerHTML = '<span class="t-ps">$</span> <span class="t-typed"></span><span class="t-cur"></span>';
        box.appendChild(cmd);
        const typed = $(".t-typed", cmd);
        for (let i = 1; i <= line.cmd.length; i++) {
          typed.textContent = line.cmd.slice(0, i);
          await sleep(28 + Math.random() * 40);
        }
        await sleep(260);
        $(".t-cur", cmd)?.remove();
        for (const o of line.out) {
          const d = document.createElement("div");
          d.className = "t-out";
          d.innerHTML = esc(o);
          d.style.opacity = "0";
          box.appendChild(d);
          try {
            animate(d, { opacity: [0, 1], duration: 300, ease: "outQuad" });
          } catch {
            d.style.opacity = "1";
          }
          await sleep(140);
        }
        await sleep(500);
      }
      await sleep(5000);
    }
  }
  const io = new IntersectionObserver((en) => {
    if (en.some((e) => e.isIntersecting)) {
      io.disconnect();
      run();
    }
  }, { threshold: 0.3 });
  io.observe(box);
})();

/* ---------- the flow diagram, animated ---------- */
(function flow() {
  const svg = $("#flow");
  if (!svg) return;
  const pktRect = $("#f-pkt-bg", svg);
  const pktText = $("#f-pkt-label", svg);
  const steps = $$(".f-step", svg);
  const refused = $("#f-refused", svg);
  const logLine = $("#f-log", svg);
  const provider = $("#f-provider", svg);
  const replay = $("#flow-replay");
  if (!pktRect || !pktText) return;

  const pos = { x: 250, y: 150 };
  const W = 120;
  const place = () => {
    pktRect.setAttribute("x", pos.x - W / 2);
    pktRect.setAttribute("y", pos.y - 15);
    pktText.setAttribute("x", pos.x);
    pktText.setAttribute("y", pos.y + 5);
  };
  const label = (text, kind) => {
    pktText.textContent = text;
    pktRect.setAttribute("class", `f-pkt ${kind}`);
  };
  const lightSteps = (on, cls = "lit") => steps.forEach((s, i) => s.classList.toggle(cls, on.includes(i)));
  const reset = () => {
    pos.x = 250;
    pos.y = 150;
    place();
    label("handle", "ok");
    pktRect.style.opacity = 1;
    pktText.style.opacity = 1;
    lightSteps([]);
    lightSteps([], "bad");
    refused.style.opacity = 0;
    logLine.textContent = "";
    provider.classList.remove("lit");
  };
  reset();

  if (reduced) {
    lightSteps([0, 1, 2, 3, 4]);
    pos.x = 600;
    place();
    return;
  }

  let tl = null;
  const build = () => {
    const t = createTimeline({ defaults: { ease: "inOutQuad" }, loop: true, onLoop: reset });
    const move = (x, y, d = 700) => t.add(pos, { x, y, duration: d, onUpdate: place });
    // Run 1: an allowed request.
    t.call(reset);
    move(425, 150, 650);
    for (let i = 0; i < 4; i++) {
      t.call(() => lightSteps([...Array(i + 1).keys()]), "+=0");
      t.add(pos, { x: 425, duration: 320 });
    }
    t.call(() => label("real key", "key"));
    move(600, 150, 200);
    move(865, 150, 650);
    t.call(() => provider.classList.add("lit"));
    t.add(pos, { x: 865, duration: 500 });
    t.call(() => {
      label("response", "resp");
      pos.y = 240;
      place();
      provider.classList.remove("lit");
    });
    move(600, 240, 650);
    t.call(() => {
      lightSteps([0, 1, 2, 3, 4]);
      label("scrubbed", "ok");
      logLine.textContent = "use   POST /v1/messages → 200";
    });
    t.add(pos, { x: 600, duration: 400 });
    move(250, 240, 650);
    t.add(pos, { x: 250, duration: 900 });
    // Run 2: a request the policy forbids stops at the broker.
    t.call(() => {
      lightSteps([]);
      pos.x = 250;
      pos.y = 150;
      place();
      label("POST /v1/refunds", "ok");
      logLine.textContent = "";
    });
    move(425, 150, 650);
    t.call(() => {
      lightSteps([0]);
      lightSteps([1], "bad");
      label("refused", "bad");
    });
    t.add(pos, { x: 425, duration: 350 });
    t.add(refused, { opacity: [0, 1], duration: 350 });
    t.call(() => {
      logLine.textContent = "deny  POST /v1/refunds   policy_denied";
    });
    t.add(pktRect, { opacity: [1, 0], duration: 500 }, "+=700");
    t.add(pktText, { opacity: [1, 0], duration: 500 }, "<<");
    t.add(pos, { x: 425, duration: 1600 });
    return t;
  };
  const start = () => {
    try {
      tl?.cancel?.();
      tl = build();
    } catch (e) {
      // Without the animation the diagram still reads: show the allowed path lit.
      lightSteps([0, 1, 2, 3, 4]);
    }
  };
  const io = new IntersectionObserver((en) => {
    if (en.some((e) => e.isIntersecting)) {
      io.disconnect();
      start();
    }
  }, { threshold: 0.4 });
  io.observe(svg);
  replay?.addEventListener("click", () => {
    reset();
    start();
  });
})();

/* ---------- paste a key, paste a handle ---------- */
(function pasteDemo() {
  const input = $("#demo-input");
  const out = $("#demo-out");
  if (!input || !out) return;
  const providers = [
    [/^sk-ant-(api|oat)\d\d-[A-Za-z0-9_-]{20,}/, "Anthropic"],
    [/^sk-proj-[A-Za-z0-9_-]{20,}/, "OpenAI"],
    [/^sk-or-v1-[a-f0-9]{40,}/, "OpenRouter"],
    [/^sk_(live|test)_[A-Za-z0-9]{16,}/, "Stripe"],
    [/^(ghp|gho|ghu|ghs)_[A-Za-z0-9]{30,}/, "GitHub"],
    [/^(AKIA|ASIA)[A-Z0-9]{16}$/, "AWS"],
    [/^xox[abp]-[A-Za-z0-9-]{20,}/, "Slack"],
    [/^AIza[0-9A-Za-z_-]{30,}/, "Google"],
    [/^SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/, "SendGrid"],
    [/^re_[A-Za-z0-9]{20,}/, "Resend"],
    [/^gsk_[A-Za-z0-9]{30,}/, "Groq"],
    [/^ntn_[A-Za-z0-9]{30,}|^secret_[A-Za-z0-9]{30,}/, "Notion"],
  ];
  const handleRe = /^usk_h_[A-Za-z0-9]{32}$/;
  const camoRe = /usk/;
  const classify = (raw) => {
    const s = raw.trim();
    if (!s) return { kind: "idle" };
    if (handleRe.test(s)) return { kind: "handle", text: "A handle. On its own it is a random string: it only works through the broker on the machine that made it, within its policy. Paste it anywhere." };
    for (const [re, name] of providers) {
      if (re.test(s)) {
        if (camoRe.test(s) && s.replace(/[^A-Za-z0-9]/g, "").length >= 22) {
          return { kind: "handle", text: `Shaped like a ${name} key, but it carries the usk marker: a camouflage handle. The SDK accepts it; the key is still in the vault.` };
        }
        return { kind: "key", text: `This looks like a real ${name} key. Pasted into a chat, a repo or a log, it is gone, and it works for whoever finds it until you rotate it.` };
      }
    }
    if (s.length >= 24 && /^[A-Za-z0-9_\-./+=]+$/.test(s) && !/\s/.test(s)) {
      return { kind: "key", text: "Unknown shape, but long and random: treat it as a secret. Put it in the vault and use a handle instead." };
    }
    return { kind: "none", text: "Not a key or a handle, as far as the patterns go." };
  };
  const render = () => {
    const r = classify(input.value);
    out.dataset.kind = r.kind;
    out.textContent = r.text || "";
  };
  input.addEventListener("input", render);
  $$("[data-sample]").forEach((b) => b.addEventListener("click", () => {
    input.value = b.dataset.sample;
    render();
    input.focus();
  }));
})();

/* ---------- policy explainer ---------- */
(function explainer() {
  const prov = $("#ex-provider");
  const pol = $("#ex-policy");
  const lines = $("#ex-lines");
  const rules = $("#ex-rules");
  const toggle = $("#ex-toggle");
  if (!prov || !pol || !lines) return;
  let data = [];
  const human = (rule) => rule;
  const render = () => {
    const p = data.find((d) => d.id === prov.value);
    const y = p?.policies.find((q) => q.id === pol.value);
    if (!p || !y) return;
    const esc = (t) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;");
    // The CLI lists every rule; on a web page the long ones fold.
    lines.innerHTML = y.lines.map((l) => l.length > 230
      ? `<li><span class="ex-short">${esc(l.slice(0, 230))}… <button class="link" type="button">more</button></span><span class="ex-full" hidden>${esc(l)}</span></li>`
      : `<li>${esc(l)}</li>`).join("");
    $$(".ex-short button", lines).forEach((b) => b.addEventListener("click", () => {
      const li = b.closest("li");
      $(".ex-short", li).hidden = true;
      $(".ex-full", li).hidden = false;
    }));
    const caps = Object.entries(y.limits || {}).map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`);
    rules.innerHTML =
      `<div class="ex-rule-group"><span class="ex-k ok">allow</span>${y.allow.map((r) => `<code>${human(r)}</code>`).join("")}</div>` +
      (y.deny.length ? `<div class="ex-rule-group"><span class="ex-k bad">deny</span>${y.deny.map((r) => `<code>${human(r)}</code>`).join("")}</div>` : "") +
      (caps.length ? `<div class="ex-rule-group"><span class="ex-k">limits</span>${caps.map((c) => `<code>${c}</code>`).join("")}</div>` : "") +
      `<div class="ex-rule-group"><span class="ex-k">hosts</span>${p.upstreams.map((h) => `<code>${h}</code>`).join("")}</div>`;
  };
  const fillPolicies = () => {
    const p = data.find((d) => d.id === prov.value);
    pol.innerHTML = (p?.policies || []).map((q) => `<option value="${q.id}">${p.id}:${q.id} — ${q.display}${q.recommended ? " (recommended)" : ""}</option>`).join("");
    render();
  };
  fetch("/presets.json")
    .then((r) => r.json())
    .then((d) => {
      data = d;
      prov.innerHTML = d.map((p) => `<option value="${p.id}">${p.display}</option>`).join("");
      prov.value = d.some((p) => p.id === "stripe") ? "stripe" : d[0].id;
      fillPolicies();
      if (pol.querySelector('option[value="payments"]')) pol.value = "payments";
      render();
    })
    .catch(() => {
      lines.innerHTML = "<li>Could not load the presets. <code>usk presets</code> lists them locally.</li>";
    });
  prov.addEventListener("change", fillPolicies);
  pol.addEventListener("change", render);
  toggle?.addEventListener("click", () => {
    const open = rules.classList.toggle("open");
    toggle.textContent = open ? "Hide the rules" : "Show the rules";
  });
})();

/* ---------- waitlist ---------- */
(function waitlist() {
  const form = $("#wl");
  const msg = $("#wl-msg");
  if (!form || !msg) return;
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const data = { email: form.email.value.trim(), role: form.role.value, note: form.note.value.trim(), website: form.website.value };
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(data.email)) {
      msg.className = "msg err";
      msg.textContent = "That email address does not look right.";
      return;
    }
    msg.className = "msg";
    msg.textContent = "Sending…";
    const fallback = 'Email <a href="mailto:hello@unseenkey.com?subject=Delegation%20waitlist">hello@unseenkey.com</a> and we will add you.';
    fetch("/api/waitlist", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(data) })
      .then((r) => r.json().catch(() => ({})).then((j) => ({ status: r.status, body: j })))
      .then((res) => {
        if (res.body && res.body.ok) {
          msg.className = "msg ok";
          msg.textContent = res.body.already ? "You are already on the list. Thank you." : "Thank you. We will write to you before the delegation beta.";
          form.reset();
        } else if (res.status === 503) {
          msg.className = "msg err";
          msg.innerHTML = `The form is not switched on yet. ${fallback}`;
        } else {
          msg.className = "msg err";
          msg.textContent = "Something went wrong. Please try again, or email hello@unseenkey.com.";
        }
      })
      .catch(() => {
        msg.className = "msg err";
        msg.innerHTML = `Could not reach the server. ${fallback}`;
      });
  });
})();

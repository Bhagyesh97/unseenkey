// The hero: a metal key that dissolves into the characters of a handle and
// back. Loaded only on wide screens without reduced motion; the page shows a
// still image otherwise. Bundled with three.js by `npm run build`.
import {
  AdditiveBlending,
  BoxGeometry,
  BufferAttribute,
  BufferGeometry,
  Color,
  DirectionalLight,
  Group,
  HemisphereLight,
  Mesh,
  MeshStandardMaterial,
  PerspectiveCamera,
  PointLight,
  Points,
  PointsMaterial,
  Scene,
  TorusGeometry,
  PMREMGenerator,
  Vector3,
  WebGLRenderer,
} from "three";
import { RoomEnvironment } from "three/examples/jsm/environments/RoomEnvironment.js";
import { MeshSurfaceSampler } from "three/examples/jsm/math/MeshSurfaceSampler.js";
import { mergeGeometries } from "three/examples/jsm/utils/BufferGeometryUtils.js";

const HANDLE = "usk_h_7Qx9mKpL2vRt";
const COUNT = 6000;

function keyGeometry() {
  const parts = [];
  const bow = new TorusGeometry(0.62, 0.17, 28, 72);
  parts.push(bow);
  const blade = new BoxGeometry(2.1, 0.28, 0.16);
  blade.translate(1.55, 0, 0);
  parts.push(blade);
  for (const [x, h] of [[1.55, 0.3], [1.9, 0.42], [2.2, 0.26], [2.5, 0.36]]) {
    const tooth = new BoxGeometry(0.18, h, 0.16);
    tooth.translate(x, -0.14 - h / 2, 0);
    parts.push(tooth);
  }
  const merged = mergeGeometries(parts, false);
  merged.center();
  return merged;
}

/** Points that spell the handle, taken from text drawn on a canvas. */
function textTargets(count) {
  const canvas = document.createElement("canvas");
  canvas.width = 900;
  canvas.height = 160;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#000";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#fff";
  ctx.font = "bold 92px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
  ctx.textBaseline = "middle";
  ctx.textAlign = "center";
  ctx.fillText(HANDLE, canvas.width / 2, canvas.height / 2 + 4);
  const { data } = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const lit = [];
  for (let y = 0; y < canvas.height; y += 2) {
    for (let x = 0; x < canvas.width; x += 2) {
      if (data[(y * canvas.width + x) * 4] > 128) lit.push(x, y);
    }
  }
  const scale = 3.7 / canvas.width;
  const out = new Float32Array(count * 3);
  for (let i = 0; i < count; i++) {
    const k = (Math.random() * (lit.length / 2)) | 0;
    out[i * 3] = (lit[k * 2] - canvas.width / 2) * scale;
    out[i * 3 + 1] = -(lit[k * 2 + 1] - canvas.height / 2) * scale;
    out[i * 3 + 2] = (Math.random() - 0.5) * 0.08;
  }
  return out;
}

export function mountHero(canvas, opts = {}) {
  const accent = new Color(opts.accent || "#0969da");
  const renderer = new WebGLRenderer({ canvas, alpha: true, antialias: true, powerPreference: "low-power" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  const scene = new Scene();
  // Metals are only as bright as what they reflect: a neutral room does it.
  const pmrem = new PMREMGenerator(renderer);
  scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
  pmrem.dispose();
  const camera = new PerspectiveCamera(32, 1, 0.1, 50);
  camera.position.set(0, 0.15, 8.2);

  scene.add(new HemisphereLight(0xffffff, 0x334455, 1.1));
  const keyLight = new DirectionalLight(0xffffff, 2.2);
  keyLight.position.set(3, 4, 5);
  scene.add(keyLight);
  const rim = new DirectionalLight(accent, 1.6);
  rim.position.set(-4, -2, -3);
  scene.add(rim);
  const glow = new PointLight(accent, 6, 12);
  glow.position.set(0, 1.5, 2.5);
  scene.add(glow);

  const group = new Group();
  scene.add(group);

  const geometry = keyGeometry();
  const material = new MeshStandardMaterial({
    color: 0xe3e7ee,
    metalness: 0.85,
    roughness: 0.22,
    envMapIntensity: 1.15,
    transparent: true,
  });
  const key = new Mesh(geometry, material);
  group.add(key);

  // Surface points of the key, and where each one goes when it dissolves.
  const sampler = new MeshSurfaceSampler(key).build();
  const from = new Float32Array(COUNT * 3);
  const tmp = new Vector3();
  for (let i = 0; i < COUNT; i++) {
    sampler.sample(tmp);
    from[i * 3] = tmp.x;
    from[i * 3 + 1] = tmp.y;
    from[i * 3 + 2] = tmp.z;
  }
  const to = textTargets(COUNT);
  const delay = new Float32Array(COUNT);
  const swirl = new Float32Array(COUNT);
  for (let i = 0; i < COUNT; i++) {
    // Points leave from the bow first and the tip last, with some scatter.
    delay[i] = Math.min(0.45, Math.max(0, (from[i * 3] + 1.6) / 3.2) * 0.35 + Math.random() * 0.12);
    swirl[i] = Math.random() * Math.PI * 2;
  }
  const positions = new Float32Array(from);
  const pGeom = new BufferGeometry();
  pGeom.setAttribute("position", new BufferAttribute(positions, 3));
  const pMat = new PointsMaterial({
    color: accent,
    size: 0.045,
    transparent: true,
    opacity: 0,
    depthWrite: false,
    blending: AdditiveBlending,
  });
  const points = new Points(pGeom, pMat);
  group.add(points);

  let t = 0; // 0 = key, 1 = handle
  let lastT = -1;
  const smooth = (u) => u * u * (3 - 2 * u);

  function applyT() {
    if (t === lastT) return;
    lastT = t;
    const attr = pGeom.getAttribute("position");
    for (let i = 0; i < COUNT; i++) {
      const d = delay[i];
      const u = smooth(Math.min(1, Math.max(0, (t - d) / (1 - d))));
      const arc = Math.sin(u * Math.PI) * 0.55;
      const i3 = i * 3;
      positions[i3] = from[i3] + (to[i3] - from[i3]) * u + Math.cos(swirl[i]) * arc * 0.6;
      positions[i3 + 1] = from[i3 + 1] + (to[i3 + 1] - from[i3 + 1]) * u + Math.sin(swirl[i]) * arc * 0.6;
      positions[i3 + 2] = from[i3 + 2] + (to[i3 + 2] - from[i3 + 2]) * u + arc * 0.4;
    }
    attr.needsUpdate = true;
    material.opacity = Math.max(0, 1 - t * 1.6);
    key.visible = material.opacity > 0.01;
    pMat.opacity = Math.min(1, t * 1.4);
    points.visible = pMat.opacity > 0.01;
  }

  // Autoplay: key for a while, dissolve into the handle, hold, come back.
  const cycle = [
    { to: 0, hold: 2600 },
    { to: 1, hold: 2600 },
  ];
  let phase = 0;
  let phaseStart = performance.now();
  const MORPH_MS = 2200;

  let pointerX = 0;
  let pointerY = 0;
  const onPointer = (e) => {
    const r = canvas.getBoundingClientRect();
    pointerX = ((e.clientX - r.left) / r.width - 0.5) * 2;
    pointerY = ((e.clientY - r.top) / r.height - 0.5) * 2;
  };
  window.addEventListener("pointermove", onPointer, { passive: true });

  function resize() {
    const w = canvas.clientWidth || 600;
    const h = canvas.clientHeight || 420;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  resize();
  window.addEventListener("resize", resize);

  let visible = true;
  const io = new IntersectionObserver((entries) => {
    visible = entries.some((en) => en.isIntersecting);
  });
  io.observe(canvas);

  let raf = 0;
  const start = performance.now();
  function frame(now) {
    raf = requestAnimationFrame(frame);
    if (!visible) return;
    const elapsed = now - phaseStart;
    const target = cycle[phase].to;
    const prev = cycle[(phase + 1) % cycle.length].to;
    if (elapsed < MORPH_MS) {
      t = prev + (target - prev) * smooth(elapsed / MORPH_MS);
    } else {
      t = target;
      if (elapsed > MORPH_MS + cycle[phase].hold) {
        phase = (phase + 1) % cycle.length;
        phaseStart = now;
      }
    }
    applyT();
    const s = (now - start) / 1000;
    group.rotation.y = Math.sin(s * 0.35) * 0.45 + pointerX * 0.25 - 0.2;
    group.rotation.x = Math.cos(s * 0.27) * 0.12 + pointerY * 0.15;
    group.position.y = Math.sin(s * 0.8) * 0.06;
    renderer.render(scene, camera);
  }
  raf = requestAnimationFrame(frame);

  return {
    /** Jump to a state for a still render: 0 = key, 1 = handle. */
    set(value) {
      phase = value >= 0.5 ? 1 : 0;
      phaseStart = performance.now() - MORPH_MS;
      t = value;
      applyT();
      renderer.render(scene, camera);
    },
    destroy() {
      cancelAnimationFrame(raf);
      window.removeEventListener("pointermove", onPointer);
      window.removeEventListener("resize", resize);
      io.disconnect();
      renderer.dispose();
    },
  };
}

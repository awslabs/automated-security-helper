/* Homepage example. Local Anime.js (MIT); no project files or scans leave the browser. */
import {
  createTimeline, createDrawable, createMotionPath, cubicBezier, stagger
} from "./vendor/anime.js";

const host = document.querySelector("[data-ash-scan]");
if (host) initialize(host);

function initialize(example) {
  const root = document.documentElement;
  const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
  const compact = matchMedia("(max-width: 620px)");
  const board = example.querySelector("[data-scan-board]");
  const canvas = example.querySelector("[data-scan-routes]");
  const play = example.querySelector("[data-scan-play]");
  const state = example.querySelector("[data-scan-state]");
  const caption = example.querySelector("[data-scan-caption]");
  const announcement = example.querySelector("[data-scan-announcement]");
  const selectors = [...example.querySelectorAll("[data-scan-category]")];
  const steps = [...example.querySelectorAll("[data-scan-step]")];
  const sourceNodes = [...example.querySelectorAll("[data-scan-source]")];
  const tracks = sourceNodes.map((source) => {
    const category = source.dataset.scanSource;
    return {
      category, source,
      engine: example.querySelector(`[data-scan-engine="${category}"]`),
      finding: example.querySelector(`[data-scan-finding="${category}"]`),
    };
  });
  const DURATION = 10000;
  const STEP_TIMES = [0, 2200, 5300, DURATION];
  const stepLabels = ["Discovering files", "Running scanners", "Collecting findings", "Writing reports"];
  const ease = cubicBezier(.32, .1, .2, 1);
  let timeline;
  let category = "all";
  let phase = -1;
  let requestedPlaying = false;
  let autoplayUsed = false;
  let inView = false;
  let layoutPending = false;
  let pointerIntent;

  const blocked = () => reducedMotion.matches || root.classList.contains("ash-motion-paused");
  const activeTrack = (track) => category === "all" || track.category === category;
  const isPlaying = () => requestedPlaying && inView && !document.hidden && !blocked();

  function describeStep(index, finished = false) {
    if (phase !== index) {
      phase = index;
      example.dataset.step = String(index);
      steps.forEach((button) => button.setAttribute("aria-pressed", String(+button.dataset.scanStep === index)));
    }
    const description = finished ? "Reports ready" : stepLabels[index];
    if (state.textContent !== description) state.textContent = description;
  }

  function updateButton() {
    const finished = !timeline || timeline.currentTime >= DURATION - 1;
    const text = reducedMotion.matches ? "Reduced motion"
      : blocked() ? "Motion paused"
        : isPlaying() ? "Pause" : finished ? "Replay" : "Play";
    play.disabled = blocked();
    play.dataset.playing = String(isPlaying());
    play.querySelector("[data-scan-play-label]").textContent = text;
    play.setAttribute("aria-label", `${text} scan example`);
  }

  function reconcilePlayback() {
    if (!timeline) return;
    if (isPlaying()) timeline.play();
    else timeline.pause();
    updateButton();
  }

  function finish() {
    requestedPlaying = false;
    timeline?.pause().seek(DURATION, true);
    describeStep(3, true);
    updateButton();
  }

  function pause() {
    requestedPlaying = false;
    timeline?.pause();
    updateButton();
  }

  function run() {
    if (blocked()) {
      finish();
      return;
    }
    autoplayUsed = true;
    if (timeline.currentTime >= DURATION - 1) timeline.seek(0, true);
    requestedPlaying = true;
    describeStep(stepAt(timeline.currentTime));
    reconcilePlayback();
  }

  function stepAt(time) {
    return time < 2200 ? 0 : time < 5300 ? 1 : time < 7800 ? 2 : 3;
  }

  function svgElement(tag, attributes) {
    const element = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, String(value)));
    return element;
  }

  function bounds(element, origin) {
    const rect = element.getBoundingClientRect();
    return {
      left: rect.left - origin.left, right: rect.right - origin.left,
      top: rect.top - origin.top, bottom: rect.bottom - origin.top,
      x: rect.left + rect.width / 2 - origin.left,
      y: rect.top + rect.height / 2 - origin.top,
    };
  }

  function route(points) {
    const { from, to, vertical } = points;
    if (vertical) {
      const middle = (from.y + to.y) / 2;
      return `M${from.x},${from.y}C${from.x},${middle} ${to.x},${middle} ${to.x},${to.y}`;
    }
    const middle = (from.x + to.x) / 2;
    return `M${from.x},${from.y}C${middle},${from.y} ${middle},${to.y} ${to.x},${to.y}`;
  }

  function makeConnection(points, track, kind) {
    const d = route(points);
    const base = svgElement("path", { d, class: "ash-scan__route" });
    const active = svgElement("path", {
      d, class: "ash-scan__route is-active", "data-kind": kind, "data-category": track.category,
    });
    const packet = svgElement("g", {
      class: `ash-scan__packet${kind === "finding" ? " ash-scan__packet--finding" : ""}`,
      "data-category": track.category,
    });
    if (kind === "finding") {
      packet.append(svgElement("circle", { r: 4 }));
    } else {
      packet.append(
        svgElement("rect", { x: -5, y: -7, width: 10, height: 14, rx: 2 }),
        svgElement("path", { d: "M0,-7v4h5", fill: "none" })
      );
    }
    canvas.append(base);
    if (activeTrack(track)) canvas.append(active, packet);
    return { active, packet, enabled: activeTrack(track) };
  }

  function rebuild() {
    const previousTime = timeline?.currentTime ?? DURATION;
    timeline?.revert();
    const origin = board.getBoundingClientRect();
    if (!origin.width || !origin.height) return;

    // Collect geometry before writing the vector layer; redraw only after layout changes.
    const positions = tracks.map((track) => ({
      source: bounds(track.source, origin),
      engine: bounds(track.engine, origin),
      finding: bounds(track.finding, origin),
    }));
    const columns = ["files", "scanners", "findings"].map((name) =>
      bounds(example.querySelector(`[data-scan-column="${name}"]`), origin));
    canvas.replaceChildren();
    canvas.setAttribute("viewBox", `0 0 ${origin.width} ${origin.height}`);

    timeline = createTimeline({
      autoplay: false,
      defaults: { ease },
      onUpdate: (self) => describeStep(stepAt(self.currentTime)),
      onComplete: () => finish(),
    });
    timeline.add(example.querySelector("[data-scan-progress]"), {
      scaleX: [0, 1], duration: DURATION, ease: "linear",
    }, 0);

    tracks.forEach((track, index) => {
      const positionsForTrack = positions[index];
      const offset = (index - 1.5) * 9;
      const inputPoints = compact.matches ? {
        from: { x: columns[0].x + offset, y: columns[0].bottom + 2 },
        to: { x: columns[1].x + offset, y: columns[1].top - 2 }, vertical: true,
      } : {
        from: { x: positionsForTrack.source.right + 2, y: positionsForTrack.source.y },
        to: { x: positionsForTrack.engine.left - 2, y: positionsForTrack.engine.y },
      };
      const outputPoints = compact.matches ? {
        from: { x: columns[1].x + offset, y: columns[1].bottom + 2 },
        to: { x: columns[2].x + offset, y: columns[2].top - 2 }, vertical: true,
      } : {
        from: { x: positionsForTrack.engine.right + 2, y: positionsForTrack.engine.y },
        to: { x: positionsForTrack.finding.left - 2, y: positionsForTrack.finding.y },
      };

      const input = makeConnection(inputPoints, track, "file");
      const output = makeConnection(outputPoints, track, "finding");
      if (!input.enabled) return;
      const drawInput = createDrawable(input.active);
      const drawOutput = createDrawable(output.active);
      const inputMotion = createMotionPath(input.active);
      const outputMotion = createMotionPath(output.active);
      const start = 220 + index * 170;
      const findingStart = 5100 + index * 150;
      const scannerProgress = track.engine.querySelector(".ash-scan__scanner-progress");
      const scannerCheck = track.engine.querySelector(".ash-scan__scanner-check");

      timeline
        .set(scannerProgress, { scaleX: 0 }, 0)
        .set(scannerCheck, { scale: .6, opacity: 0 }, 0)
        .add(drawInput, { draw: ["0 0", "0 1"], duration: 1050 }, start)
        .add(input.packet, {
          translateX: inputMotion.translateX, translateY: inputMotion.translateY,
          opacity: [0, 1], duration: 1200,
        }, start + 80)
        .add(input.packet, { opacity: 0, duration: 160 }, start + 1280)
        .add(scannerProgress, {
          scaleX: [0, 1], duration: 1700,
        }, 2200 + index * 100)
        .add(scannerCheck, {
          scale: [.6, 1], opacity: [0, 1], duration: 320,
        }, 4100 + index * 100)
        .add(drawOutput, { draw: ["0 0", "0 1"], duration: 1050 }, findingStart)
        .add(output.packet, {
          translateX: outputMotion.translateX, translateY: outputMotion.translateY,
          opacity: [0, 1], duration: 1200,
        }, findingStart + 100)
        .add(output.packet, { opacity: 0, duration: 160 }, findingStart + 1300)
        .add(track.finding, { translateY: [5, 0], duration: 400 }, findingStart + 1100);
    });

    timeline
      .set(example.querySelector("[data-scan-coverage] .ash-icon"), {
        scale: .7, opacity: 0,
      }, 0)
      .set(example.querySelectorAll(".ash-scan__report-lines i"), { scaleX: 0 }, 0)
      .add(example.querySelector("[data-scan-coverage] .ash-icon"), {
        scale: [.7, 1], opacity: [0, 1], duration: 320,
      }, 7500)
      .add(example.querySelector("[data-scan-report]"), {
        translateY: [6, 0], duration: 500,
      }, 7850)
      .add(example.querySelectorAll(".ash-scan__report-lines i"), {
        scaleX: [0, 1], duration: 700, delay: stagger(90),
      }, 8100)
      .add(example.querySelectorAll("[data-scan-format]"), {
        translateY: [4, 0], duration: 500, delay: stagger(80),
      }, 8800);

    // Seeking is also the static and reduced-motion renderer, not a separate approximation.
    timeline.seek(Math.min(previousTime, DURATION), true);
    if (previousTime >= DURATION - 1 || blocked()) finish();
    else {
      describeStep(stepAt(previousTime));
      reconcilePlayback();
    }
  }

  function selectCategory(selected) {
    category = selected;
    example.dataset.category = selected;
    selectors.forEach((button) => {
      button.setAttribute("aria-pressed", String(button.dataset.scanCategory === selected));
    });
    tracks.forEach((track) => {
      [track.source, track.engine, track.finding].forEach((node) => node.classList.toggle("is-selected", activeTrack(track)));
    });
    const track = tracks.find((candidate) => candidate.category === category);
    const description = track
      ? `${track.source.querySelector("code").textContent} → ${track.engine.querySelector(".ash-scan__scanner-names").innerText.replace(/\n/g, ", ")} → ${track.finding.lastElementChild.textContent}.`
      : "Select a file to trace its scan. Example data.";
    caption.textContent = description;
    announcement.textContent = track ? `Example flow: ${description}` : "Showing all example file groups.";
    pause();
    rebuild();
    if (blocked()) finish();
    else {
      timeline.seek(0, true);
      run();
    }
  }

  selectors.forEach((button) => {
    button.disabled = false;
    button.addEventListener("click", () => selectCategory(button.dataset.scanCategory));
  });
  steps.forEach((button) => {
    button.addEventListener("click", () => {
      autoplayUsed = true;
      pause();
      const index = +button.dataset.scanStep;
      timeline.seek(STEP_TIMES[index], true);
      describeStep(index, index === 3);
      updateButton();
      announcement.textContent = `Example step ${index + 1}: ${button.textContent.trim().replace(/^0\d\s*/, "")}.`;
    });
  });
  play.addEventListener("pointerdown", () => { pointerIntent = isPlaying(); });
  play.addEventListener("pointercancel", () => { pointerIntent = undefined; });
  play.addEventListener("click", () => {
    const shouldPause = pointerIntent ?? isPlaying();
    pointerIntent = undefined;
    if (shouldPause) pause();
    else run();
  });
  example.addEventListener("focusin", () => {
    autoplayUsed = true;
    pause();
  });
  document.addEventListener("visibilitychange", reconcilePlayback);
  window.addEventListener("ash:motionchange", () => {
    if (blocked()) finish();
    else updateButton();
  });
  reducedMotion.addEventListener("change", () => {
    if (blocked()) finish();
    else updateButton();
  });

  function scheduleLayout() {
    if (layoutPending) return;
    layoutPending = true;
    requestAnimationFrame(() => {
      layoutPending = false;
      rebuild();
    });
  }
  if ("ResizeObserver" in window) new ResizeObserver(scheduleLayout).observe(board);
  else window.addEventListener("resize", scheduleLayout, { passive: true });
  document.fonts?.ready.then(scheduleLayout);
  rebuild();
  example.classList.add("is-ready");
  caption.textContent = "Select a file to trace its scan. Example data.";

  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver((entries) => {
      inView = entries.some((entry) => entry.isIntersecting);
      if (inView && !autoplayUsed && !blocked() && !example.contains(document.activeElement)) {
        timeline.seek(0, true);
        run();
      } else reconcilePlayback();
    }, { threshold: .15 });
    observer.observe(example);
  } else {
    inView = true;
    finish();
  }
}

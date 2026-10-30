/* charts.js — tiny dependency-free SVG charts for the VAPT dashboard.
   No external library: works fully offline. Colours come from CSS custom
   properties so charts follow the light/dark theme automatically. */
(function () {
  "use strict";

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  // Map a severity / status / rto label to its theme colour.
  function colorFor(label) {
    const m = {
      "Critical": "--crit", "High": "--high", "Medium": "--med",
      "Low": "--low", "Information": "--info",
      "Met": "--met", "Breached": "--breach", "Not Applicable": "--ink-faint",
      "Open": "--accent", "Fixed": "--low", "Pending": "--ink-faint",
      "In progress": "--med", "On hold": "--high", "Testing": "--accent",
      "Reported": "--info", "Risk Accepted": "--ink-faint", "Exception Approved": "--info",
      "Yes": "--crit", "No": "--low", "Unknown": "--ink-faint",
    };
    return cssVar(m[label] || "--accent") || "#4c9aff";
  }

  const PALETTE = ["--accent", "--low", "--med", "--high", "--crit", "--info"];
  function paletteColor(i) { return cssVar(PALETTE[i % PALETTE.length]); }

  // ---- Donut chart -------------------------------------------------------
  // data: [{label, value}], returns an SVG element + legend built into container.
  function donut(container, data, opts) {
    opts = opts || {};
    const total = data.reduce((s, d) => s + d.value, 0);
    const size = opts.size || 150, stroke = opts.stroke || 24;
    const r = (size - stroke) / 2, cx = size / 2, cy = size / 2;
    const circ = 2 * Math.PI * r;
    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("width", size); svg.setAttribute("height", size);
    svg.setAttribute("viewBox", `0 0 ${size} ${size}`);

    // track
    const track = document.createElementNS(svgNS, "circle");
    track.setAttribute("cx", cx); track.setAttribute("cy", cy); track.setAttribute("r", r);
    track.setAttribute("fill", "none"); track.setAttribute("stroke", cssVar("--panel-2"));
    track.setAttribute("stroke-width", stroke);
    svg.appendChild(track);

    let offset = 0;
    data.forEach((d) => {
      if (d.value <= 0) return;
      const frac = d.value / total;
      const seg = document.createElementNS(svgNS, "circle");
      seg.setAttribute("cx", cx); seg.setAttribute("cy", cy); seg.setAttribute("r", r);
      seg.setAttribute("fill", "none");
      seg.setAttribute("stroke", d.color || colorFor(d.label));
      seg.setAttribute("stroke-width", stroke);
      seg.setAttribute("stroke-dasharray", `${frac * circ} ${circ}`);
      seg.setAttribute("stroke-dashoffset", -offset * circ);
      seg.setAttribute("transform", `rotate(-90 ${cx} ${cy})`);
      seg.style.transition = "stroke-dasharray .7s cubic-bezier(.22,1,.36,1)";
      const t = document.createElementNS(svgNS, "title");
      t.textContent = `${d.label}: ${d.value} (${Math.round(frac * 100)}%)`;
      seg.appendChild(t);
      svg.appendChild(seg);
      offset += frac;
    });

    // center label
    if (opts.centerLabel !== false) {
      const big = document.createElementNS(svgNS, "text");
      big.setAttribute("x", cx); big.setAttribute("y", cy - 2);
      big.setAttribute("text-anchor", "middle"); big.setAttribute("dominant-baseline", "middle");
      big.setAttribute("fill", cssVar("--ink"));
      big.setAttribute("font-size", "22"); big.setAttribute("font-weight", "600");
      big.setAttribute("font-family", cssVar("--mono") || "monospace");
      big.textContent = opts.centerValue != null ? opts.centerValue : total;
      svg.appendChild(big);
      const sub = document.createElementNS(svgNS, "text");
      sub.setAttribute("x", cx); sub.setAttribute("y", cy + 16);
      sub.setAttribute("text-anchor", "middle"); sub.setAttribute("dominant-baseline", "middle");
      sub.setAttribute("fill", cssVar("--ink-faint"));
      sub.setAttribute("font-size", "10");
      sub.textContent = opts.centerLabelText || "total";
      svg.appendChild(sub);
    }

    const wrap = document.createElement("div");
    wrap.className = "donut-wrap";
    wrap.appendChild(svg);

    // legend
    const legend = document.createElement("div");
    legend.className = "legend";
    data.forEach((d) => {
      const li = document.createElement("div"); li.className = "li";
      const sw = document.createElement("span"); sw.className = "sw";
      sw.style.background = d.color || colorFor(d.label);
      const ln = document.createElement("span"); ln.className = "ln"; ln.textContent = d.label;
      const lv = document.createElement("span"); lv.className = "lv"; lv.textContent = d.value;
      li.appendChild(sw); li.appendChild(ln); li.appendChild(lv);
      legend.appendChild(li);
    });
    wrap.appendChild(legend);

    container.innerHTML = "";
    container.appendChild(wrap);
  }

  // ---- Horizontal bars ---------------------------------------------------
  // data: [{label, value, color?}]
  function hbars(container, data, opts) {
    opts = opts || {};
    const max = Math.max(1, ...data.map((d) => d.value));
    const box = document.createElement("div"); box.className = "hbars";
    data.forEach((d, i) => {
      const row = document.createElement("div"); row.className = "hbar";
      const label = document.createElement("div"); label.className = "hb-label";
      label.textContent = d.label; label.title = d.label;
      const track = document.createElement("div"); track.className = "hb-track";
      const fill = document.createElement("div"); fill.className = "hb-fill";
      fill.style.background = d.color || (opts.byLabel ? colorFor(d.label) : paletteColor(i));
      fill.style.width = "0%";
      track.appendChild(fill);
      const val = document.createElement("div"); val.className = "hb-val"; val.textContent = d.value;
      row.appendChild(label); row.appendChild(track); row.appendChild(val);
      box.appendChild(row);
      // animate after insert
      requestAnimationFrame(() => { fill.style.width = (100 * d.value / max) + "%"; });
    });
    container.innerHTML = "";
    container.appendChild(box);
  }

  window.VChart = { donut: donut, hbars: hbars, colorFor: colorFor };
})();

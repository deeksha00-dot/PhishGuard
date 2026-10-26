/* PhishGuard front-end. Talks to the Flask API with fetch().
   All user-submitted text is inserted with textContent / text nodes (never innerHTML). */
(function () {
  "use strict";

  var API = {
    analyze: "/api/analyze",
    history: "/api/history",
    historyItem: function (id) { return "/api/history/" + encodeURIComponent(id); }
  };

  var EXAMPLES = {
    otp: "ALERT: Your bank account is suspended. Urgent action required within 24 hours. Reply with your OTP and click http://bit.ly/secure-bank-verify to avoid account closure.",
    prize: "Congratulations! You have won a lottery prize of $50,000. Pay a small processing fee and keep this confidential. Claim your prize at http://claim-prize-now.xyz/win",
    ip: "Your parcel is on hold. Confirm your delivery address and pay the customs fee here: http://192.168.4.23/track/login",
    safe: "Hi Riya, are we still meeting for lunch tomorrow at 1pm? I went to the bank this morning, so I'm free after that.",
    legit: "Your OTP for the card payment of Rs 499 is 482913. Never share it with anyone, including bank staff."
  };

  var $ = function (id) { return document.getElementById(id); };
  var input = $("content-input"), typeSelect = $("input-type");
  var analyzeBtn = $("analyze-btn"), clearBtn = $("clear-btn");
  var formError = $("form-error"), charCount = $("char-count");
  var resEmpty = $("result-empty"), resLoading = $("result-loading"), resBody = $("result-body"), resCard = $("results");
  var historyList = $("history-list"), historyEmpty = $("history-empty"), historyError = $("history-error");
  var clearHistoryBtn = $("clear-history-btn"), dialog = $("confirm-dialog");
  var busy = false;
  var MAX = parseInt(input.getAttribute("maxlength"), 10) || 10000;

  /* ---------- tiny DOM helpers ---------- */
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }
  function showError(node, message) { node.textContent = message; node.hidden = false; }
  function hideError(node) { node.textContent = ""; node.hidden = true; }
  function levelClass(level) { return "level-" + String(level).toLowerCase(); }
  function levelColor(level) {
    var map = { low: "--low", medium: "--medium", high: "--high", critical: "--critical" };
    return getComputedStyle(document.documentElement).getPropertyValue(map[String(level).toLowerCase()] || "--cyan");
  }
  function formatDate(iso) {
    var d = new Date(iso);
    return isNaN(d) ? String(iso) : d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  }

  /* ---------- API wrapper with friendly errors ---------- */
  function api(url, options) {
    return fetch(url, options).then(function (response) {
      return response.json().catch(function () { return null; }).then(function (data) {
        if (!response.ok) {
          var message = data && data.error ? data.error : "The server returned an error (" + response.status + ").";
          throw new Error(message);
        }
        if (data === null) throw new Error("The server sent an unexpected response.");
        return data;
      });
    }, function () {
      throw new Error("Cannot reach the PhishGuard server. Make sure it is running (python app.py) and reload this page.");
    });
  }

  /* ---------- Rendering the result ---------- */
  function validResult(r) {
    return r && typeof r.risk_score === "number" && typeof r.risk_level === "string" &&
      Array.isArray(r.detected_indicators) && Array.isArray(r.recommendations);
  }

  // Build the message with <mark> around suspicious phrases, using text nodes only.
  function highlightedMessage(text, result) {
    var shown = String(text).replace(/\r\n?/g, "\n").replace(/[ \t\f\v]+/g, " ")
      .replace(/[\u2018\u2019]/g, "'").replace(/[\u201c\u201d]/g, '"').trim();
    var lower = shown.toLowerCase();
    var needles = (result.suspicious_phrases || []).slice();
    (result.detected_urls || []).forEach(function (u) { if (u && u.url) needles.push(u.url); });
    var ranges = [];
    needles.forEach(function (needle) {
      var n = String(needle).toLowerCase();
      if (!n) return;
      var from = 0, idx;
      while ((idx = lower.indexOf(n, from)) !== -1) { ranges.push([idx, idx + n.length]); from = idx + n.length; }
    });
    ranges.sort(function (a, b) { return a[0] - b[0]; });
    var merged = [];
    ranges.forEach(function (r) {
      var last = merged[merged.length - 1];
      if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]); else merged.push([r[0], r[1]]);
    });
    var box = el("div", "msg-box");
    var pos = 0;
    merged.forEach(function (r) {
      if (r[0] > pos) box.appendChild(document.createTextNode(shown.slice(pos, r[0])));
      box.appendChild(el("mark", null, shown.slice(r[0], r[1])));
      pos = r[1];
    });
    if (pos < shown.length) box.appendChild(document.createTextNode(shown.slice(pos)));
    return box;
  }

  function gauge(score, level) {
    var NS = "http://www.w3.org/2000/svg", R = 54, C = 2 * Math.PI * R;
    var wrap = el("div", "gauge " + levelClass(level));
    var svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 132 132");
    svg.setAttribute("aria-hidden", "true");
    function circle(cls) {
      var c = document.createElementNS(NS, "circle");
      c.setAttribute("cx", "66"); c.setAttribute("cy", "66"); c.setAttribute("r", String(R));
      c.setAttribute("fill", "none"); c.setAttribute("stroke-width", "12");
      c.setAttribute("class", cls);
      return c;
    }
    var track = circle("track");
    var arc = circle("arc");
    arc.setAttribute("stroke", levelColor(level));
    arc.setAttribute("stroke-linecap", "round");
    arc.setAttribute("stroke-dasharray", String(C));
    arc.setAttribute("stroke-dashoffset", String(C));
    svg.appendChild(track); svg.appendChild(arc);
    wrap.appendChild(svg);
    var num = el("div", "gauge-num");
    var inner = el("div", null, String(score));
    inner.appendChild(el("small", null, "out of 100"));
    num.appendChild(inner);
    wrap.appendChild(num);
    // animate after insertion
    requestAnimationFrame(function () { requestAnimationFrame(function () {
      arc.setAttribute("stroke-dashoffset", String(C * (1 - score / 100)));
    }); });
    return wrap;
  }

  function section(title) {
    var s = el("div", "result-section");
    s.appendChild(el("h3", null, title));
    return s;
  }

  function renderResult(result, submittedText) {
    resBody.textContent = "";

    var head = el("div", "score-head");
    head.appendChild(gauge(result.risk_score, result.risk_level));
    var right = el("div");
    right.appendChild(el("span", "badge " + levelClass(result.risk_level), result.risk_level + " risk"));
    right.appendChild(el("p", null, "Risk score: " + result.risk_score + "/100"));
    right.appendChild(el("p", "muted small", "Content type: " + (result.input_type === "url" ? "URL" : "Email / SMS")));
    head.appendChild(right);
    resBody.appendChild(head);

    var meter = el("div", "meter " + levelClass(result.risk_level));
    meter.setAttribute("role", "progressbar");
    meter.setAttribute("aria-valuemin", "0"); meter.setAttribute("aria-valuemax", "100");
    meter.setAttribute("aria-valuenow", String(result.risk_score));
    meter.setAttribute("aria-label", "Risk score");
    var fill = el("div"); fill.style.width = "0%";
    meter.appendChild(fill);
    resBody.appendChild(meter);
    requestAnimationFrame(function () { requestAnimationFrame(function () { fill.style.width = result.risk_score + "%"; }); });

    if (result.summary) resBody.appendChild(el("p", null, result.summary));

    // Detected indicators with the points each one added
    var sInd = section("Warning signs detected");
    if (result.detected_indicators.length === 0) {
      sInd.appendChild(el("p", "muted", "No common phishing or scam indicators were found."));
    } else {
      var ul = el("ul", "indicator-list");
      result.detected_indicators.forEach(function (ind) {
        var li = el("li", "indicator");
        li.appendChild(el("span", "pts", "+" + ind.points));
        li.appendChild(document.createTextNode(ind.description));
        if (ind.evidence && ind.evidence.length) li.appendChild(el("span", "ev", "Found: " + ind.evidence.join("  |  ")));
        ul.appendChild(li);
      });
      sInd.appendChild(ul);
    }
    resBody.appendChild(sInd);

    // Score breakdown (only on fresh analyses; history rows don't store it)
    if (Array.isArray(result.score_breakdown) && result.score_breakdown.length) {
      var sB = section("How the score was built");
      var table = el("table", "breakdown");
      var thead = el("thead"), hr = el("tr");
      hr.appendChild(el("th", null, "Category")); hr.appendChild(el("th", null, "Points"));
      thead.appendChild(hr); table.appendChild(thead);
      var tbody = el("tbody");
      result.score_breakdown.forEach(function (row) {
        var tr = el("tr");
        tr.appendChild(el("td", null, row.category));
        tr.appendChild(el("td", null, row.capped ? row.points + " (capped from " + row.raw_points + ")" : String(row.points)));
        tbody.appendChild(tr);
      });
      table.appendChild(tbody); sB.appendChild(table);
      resBody.appendChild(sB);
    }

    // Highlighted message
    if (submittedText && ((result.suspicious_phrases || []).length || (result.detected_urls || []).length)) {
      var sMsg = section("Suspicious phrases highlighted");
      sMsg.appendChild(highlightedMessage(submittedText, result));
      resBody.appendChild(sMsg);
    }

    // URLs (static inspection only)
    if ((result.detected_urls || []).length) {
      var sUrl = section("Links found (not opened)");
      result.detected_urls.forEach(function (u) {
        var item = el("div", "url-item", u.url);
        var issues = u.issue_descriptions || [];
        if (issues.length) issues.forEach(function (d) { item.appendChild(el("span", "url-issue", d)); });
        else item.appendChild(el("span", "url-ok", "No structural red flags found. This does not prove the site is safe."));
        sUrl.appendChild(item);
      });
      sUrl.appendChild(el("p", "muted small", "PhishGuard inspects URL text only. It does not visit links or check live reputation."));
      resBody.appendChild(sUrl);
    }

    var sRec = section("What to do");
    var rl = el("ul", "plain-list");
    result.recommendations.forEach(function (r) { rl.appendChild(el("li", null, r)); });
    sRec.appendChild(rl);
    resBody.appendChild(sRec);

    resBody.appendChild(el("p", "disclaimer-line",
      result.disclaimer || "This score is a heuristic estimate, not a guarantee of safety."));

    resEmpty.hidden = true; resLoading.hidden = true; resBody.hidden = false;
  }

  /* ---------- Analyze flow ---------- */
  function setBusy(state) {
    busy = state;
    analyzeBtn.disabled = state;
    analyzeBtn.textContent = state ? "Analyzing..." : "Analyze Message";
    if (state) { resEmpty.hidden = true; resBody.hidden = true; resLoading.hidden = false; }
  }

  function analyze() {
    if (busy) return;
    hideError(formError);
    var text = input.value;
    if (!text.trim()) { showError(formError, "Paste a message or link first, then choose Analyze Message."); input.focus(); return; }
    if (text.length > MAX) { showError(formError, "That is too long. The limit is " + MAX + " characters."); return; }

    setBusy(true);
    api(API.analyze, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text, input_type: typeSelect.value })
    }).then(function (result) {
      if (!validResult(result)) throw new Error("The server sent an unexpected response.");
      renderResult(result, text);
      resCard.focus({ preventScroll: true });
      if (window.matchMedia("(max-width: 980px)").matches) resCard.scrollIntoView({ behavior: "smooth", block: "start" });
      loadHistory();
    }).catch(function (err) {
      resLoading.hidden = true;
      resBody.hidden = true;
      resEmpty.hidden = false;
      showError(formError, err.message);
    }).then(function () { setBusy(false); });
  }

  /* ---------- History ---------- */
  function renderStats(items) {
    $("stat-total").textContent = String(items.length);
    if (!items.length) { $("stat-max").textContent = "-"; $("stat-avg").textContent = "-"; return; }
    var max = 0, sum = 0;
    items.forEach(function (i) { max = Math.max(max, i.risk_score); sum += i.risk_score; });
    $("stat-max").textContent = String(max);
    $("stat-avg").textContent = String(Math.round(sum / items.length));
  }

  function renderHistory(items) {
    historyList.textContent = "";
    historyEmpty.hidden = items.length > 0;
    clearHistoryBtn.disabled = items.length === 0;
    items.forEach(function (item) {
      var li = el("li");
      var btn = el("button", "history-item");
      btn.type = "button";
      btn.setAttribute("aria-label", "Open analysis from " + formatDate(item.created_at) + ", " + item.risk_level + " risk, score " + item.risk_score);
      btn.appendChild(el("span", "h-score " + levelClass(item.risk_level), String(item.risk_score)));
      var mid = el("span");
      mid.appendChild(el("span", "h-preview", item.preview || "(empty)"));
      mid.appendChild(el("span", "h-meta", formatDate(item.created_at)));
      btn.appendChild(mid);
      btn.appendChild(el("span", "h-level " + levelClass(item.risk_level), item.risk_level));
      btn.addEventListener("click", function () { openSaved(item.id); });
      li.appendChild(btn);
      historyList.appendChild(li);
    });
    renderStats(items);
  }

  function loadHistory() {
    return api(API.history).then(function (data) {
      if (!data || !Array.isArray(data.history)) throw new Error("The server sent an unexpected response.");
      hideError(historyError);
      renderHistory(data.history);
    }).catch(function (err) { showError(historyError, err.message); });
  }

  function openSaved(id) {
    hideError(formError);
    api(API.historyItem(id)).then(function (item) {
      if (!validResult(item)) throw new Error("The server sent an unexpected response.");
      input.value = item.submitted_text || "";
      updateCount();
      renderResult(item, item.submitted_text);
      document.getElementById("analyze").scrollIntoView({ behavior: "smooth", block: "start" });
    }).catch(function (err) { showError(historyError, err.message); });
  }

  function clearHistory() {
    api(API.history, { method: "DELETE" }).then(function () {
      hideError(historyError);
      return loadHistory();
    }).catch(function (err) { showError(historyError, err.message); });
  }

  /* ---------- Wiring ---------- */
  function updateCount() { charCount.textContent = input.value.length + " / " + MAX; }
  input.addEventListener("input", updateCount);
  input.addEventListener("keydown", function (e) { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") analyze(); });
  analyzeBtn.addEventListener("click", analyze);

  clearBtn.addEventListener("click", function () {
    input.value = ""; updateCount(); hideError(formError);
    resBody.hidden = true; resLoading.hidden = true; resEmpty.hidden = false;
    input.focus();
  });

  $("examples").addEventListener("click", function (e) {
    var key = e.target && e.target.getAttribute && e.target.getAttribute("data-example");
    if (!key || !EXAMPLES[key]) return;
    input.value = EXAMPLES[key]; typeSelect.value = "auto"; updateCount(); hideError(formError); input.focus();
  });

  clearHistoryBtn.addEventListener("click", function () {
    if (typeof dialog.showModal === "function") dialog.showModal();
    else if (window.confirm("Delete all saved analyses? This cannot be undone.")) clearHistory();
  });
  dialog.addEventListener("close", function () { if (dialog.returnValue === "confirm") clearHistory(); });

  updateCount();
  loadHistory();
})();

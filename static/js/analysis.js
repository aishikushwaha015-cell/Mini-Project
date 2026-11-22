/* ==================================================================== */
/* DRISHTI AI — Analysis modules front-end                               */
/*                                                                      */
/* Talks to the existing Flask APIs without changing them:              */
/*   /predict, /detect-text, /analyze-image, /analyze-brand,            */
/*   /analyze-login-form, /assess-risk                                  */
/*                                                                      */
/* Privacy: only sanitized result snapshots (scores, labels, reasons)   */
/* are ever written to sessionStorage. Raw URLs, messages, OCR text,    */
/* HTML and uploaded image bytes are never stored by this script.       */
/* ==================================================================== */

(function () {
  'use strict';

  var MODULE_KEYS = ['url', 'text', 'ocr', 'brand', 'login_form'];

  var MODULE_LABELS = {
    url: 'URL Analysis',
    text: 'Text Analysis',
    ocr: 'Image OCR',
    brand: 'Brand Logo',
    login_form: 'Login Form'
  };

  var MODULE_LINKS = {
    url: '/analysis/url',
    text: '/analysis/text',
    ocr: '/analysis/ocr',
    brand: '/analysis/image-brand',
    login_form: '/analysis/login-form'
  };

  var STORE_PREFIX = 'phishguard.module.';
  var MAX_IMAGE_BYTES = 5 * 1024 * 1024;
  var MAX_HTML_BYTES = 2 * 1024 * 1024;

  /* ---------------------------------------------------------------- */
  /* Small DOM helpers (text-only insertion, never innerHTML)         */
  /* ---------------------------------------------------------------- */

  function byId(id) {
    return document.getElementById(id);
  }

  function make(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  function clearNode(node) {
    while (node && node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  /* ---------------------------------------------------------------- */
  /* Labels, tones and formatting                                     */
  /* ---------------------------------------------------------------- */

  function toneFor(value) {
    var key = String(value === null || value === undefined ? '' : value)
      .trim()
      .toLowerCase();
    if (key === 'safe' || key === 'legitimate') {
      return 'safe';
    }
    if (key === 'suspicious') {
      return 'suspicious';
    }
    if (key === 'high risk' || key === 'phishing') {
      return 'high-risk';
    }
    if (key === 'possible match') {
      return 'info';
    }
    return 'neutral';
  }

  function progressClass(tone) {
    if (tone === 'safe') {
      return 'progress-fill-safe';
    }
    if (tone === 'suspicious') {
      return 'progress-fill-suspicious';
    }
    if (tone === 'high-risk') {
      return 'progress-fill-high';
    }
    return '';
  }

  function statusClass(tone) {
    if (tone === 'safe') {
      return 'is-safe';
    }
    if (tone === 'suspicious') {
      return 'is-warn';
    }
    if (tone === 'high-risk') {
      return 'is-danger';
    }
    if (tone === 'info') {
      return 'is-ready';
    }
    return '';
  }

  function guidanceFor(level) {
    var tone = toneFor(level);
    if (tone === 'safe') {
      return [
        'No strong phishing indicators were found, but stay cautious.',
        'Verify unexpected requests before sharing any information.'
      ];
    }
    if (tone === 'suspicious') {
      return [
        'Verify the sender or website independently before acting.',
        'Avoid entering credentials until the request is confirmed.',
        'Check the address carefully and prefer typing it manually.'
      ];
    }
    return [
      'Do not enter passwords, OTPs or personal information.',
      'Do not click links or download attachments from this source.',
      'Verify the sender or website through an official channel you find yourself.',
      'Report it to your IT or security team.'
    ];
  }

  function formatValue(value) {
    if (value === null || value === undefined || value === '') {
      return '\u2014';
    }
    return String(value);
  }

  function formatBytes(bytes) {
    if (typeof bytes !== 'number' || !isFinite(bytes) || bytes <= 0) {
      return '0 B';
    }
    if (bytes < 1024) {
      return bytes + ' B';
    }
    if (bytes < 1024 * 1024) {
      return (bytes / 1024).toFixed(1) + ' KB';
    }
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function formatTime(timestamp) {
    try {
      return new Date(timestamp).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch (error) {
      return '';
    }
  }

  function percent(value) {
    var number = Number(value);
    if (!isFinite(number)) {
      return '\u2014';
    }
    return Math.round(number * 100) + '%';
  }

  /* ---------------------------------------------------------------- */
  /* Alerts, busy state and networking                                */
  /* ---------------------------------------------------------------- */

  function showAlert(box, message, tone) {
    if (!box) {
      return;
    }
    box.className = 'alert alert-' + (tone || 'error') + ' form-alert';
    box.textContent = String(message);
    box.hidden = false;
  }

  function hideAlert(box) {
    if (!box) {
      return;
    }
    box.textContent = '';
    box.hidden = true;
  }

  function makeAlertNode(tone, message) {
    return make('div', 'alert alert-' + (tone || 'info'), message);
  }

  function setBusy(button, busy) {
    if (!button) {
      return;
    }
    button.disabled = busy;
    button.classList.toggle('is-loading', busy);
    button.setAttribute('aria-busy', busy ? 'true' : 'false');
    var label = button.querySelector('.btn-label');
    if (label) {
      if (!label.dataset.idleText) {
        label.dataset.idleText = label.textContent;
      }
      label.textContent = busy
        ? button.dataset.busyLabel || 'Analyzing\u2026'
        : label.dataset.idleText;
    }
  }

  async function handleResponse(response) {
    var raw = '';
    try {
      raw = await response.text();
    } catch (error) {
      raw = '';
    }
    var data = null;
    if (raw) {
      try {
        data = JSON.parse(raw);
      } catch (error) {
        data = null;
      }
    }
    if (!response.ok) {
      var message =
        data && typeof data.error === 'string'
          ? data.error
          : 'The request could not be completed (HTTP ' + response.status + ').';
      var failure = new Error(message);
      failure.status = response.status;
      throw failure;
    }
    if (!data || typeof data !== 'object') {
      throw new Error('The server returned an unexpected response.');
    }
    return data;
  }

  function requestJSON(url, payload) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(handleResponse);
  }

  function requestForm(url, formData) {
    return fetch(url, { method: 'POST', body: formData }).then(handleResponse);
  }

  /* ---------------------------------------------------------------- */
  /* Result card construction                                         */
  /* ---------------------------------------------------------------- */

  function kvGrid(items) {
    var dl = make('dl', 'kv-grid');
    items.forEach(function (item) {
      if (!item) {
        return;
      }
      var wrap = make('div', 'kv');
      wrap.appendChild(make('dt', null, item.label));
      wrap.appendChild(make('dd', null, formatValue(item.value)));
      dl.appendChild(wrap);
    });
    return dl;
  }

  function reasonList(items, modifier) {
    var ul = make('ul', 'reason-list' + (modifier ? ' ' + modifier : ''));
    items.forEach(function (text) {
      if (text === null || text === undefined) {
        return;
      }
      ul.appendChild(make('li', 'reason-item', String(text)));
    });
    return ul;
  }

  function section(title, content) {
    var wrapper = make('section', 'result-section');
    wrapper.appendChild(make('h3', null, title));
    wrapper.appendChild(content);
    return wrapper;
  }

  function resultCard(options) {
    var card = make('article', 'result-card');

    var head = make('div', 'result-head');
    var titles = make('div');
    titles.appendChild(make('p', 'result-kicker', options.kicker || 'Analysis result'));
    titles.appendChild(make('h2', null, options.title || 'Result'));
    head.appendChild(titles);
    head.appendChild(
      make('span', 'badge badge-' + (options.tone || 'neutral'), options.level || '\u2014')
    );
    card.appendChild(head);

    if (typeof options.score === 'number' && isFinite(options.score)) {
      var score = Math.max(0, Math.min(100, options.score));
      var scoreWrap = make('div', 'result-score-wrap');
      var scoreLine = make('div', 'result-score-line');
      scoreLine.appendChild(
        make(
          'span',
          'result-score tone-' + (options.scoreTone || options.tone || 'info'),
          String(options.score)
        )
      );
      scoreLine.appendChild(
        make('span', 'result-score-denom', options.scoreDenom || '/ 100')
      );
      scoreWrap.appendChild(scoreLine);

      var progress = make('div', 'progress');
      progress.setAttribute('role', 'progressbar');
      progress.setAttribute('aria-valuemin', '0');
      progress.setAttribute('aria-valuemax', '100');
      progress.setAttribute('aria-valuenow', String(options.score));
      var fill = make('span', 'progress-fill ' + progressClass(options.tone));
      fill.style.width = score + '%';
      progress.appendChild(fill);
      scoreWrap.appendChild(progress);
      card.appendChild(scoreWrap);
    }

    var bodyNodes = [];
    if (options.meta && options.meta.length) {
      bodyNodes.push(kvGrid(options.meta));
    }
    if (options.reasons && options.reasons.length) {
      bodyNodes.push(section('Reasons', reasonList(options.reasons)));
    }
    if (options.recommendations && options.recommendations.length) {
      bodyNodes.push(
        section(
          'Recommended next steps',
          reasonList(options.recommendations, 'recommendation-list')
        )
      );
    }
    (options.extra || []).forEach(function (node) {
      if (node) {
        bodyNodes.push(node);
      }
    });
    if (options.note) {
      bodyNodes.push(make('p', 'result-note', options.note));
    }

    if (bodyNodes.length) {
      var body = make('div', 'result-body');
      bodyNodes.forEach(function (node) {
        body.appendChild(node);
      });
      card.appendChild(body);
    }

    return card;
  }

  function renderResult(container, node) {
    if (!container) {
      return;
    }
    container.setAttribute('aria-busy', 'false');
    clearNode(container);
    container.appendChild(node);
  }

  /* ---------------------------------------------------------------- */
  /* Sanitized session snapshots                                      */
  /* ---------------------------------------------------------------- */

  function saveSnapshot(key, result) {
    try {
      sessionStorage.setItem(
        STORE_PREFIX + key,
        JSON.stringify({ savedAt: Date.now(), result: result })
      );
    } catch (error) {
      /* Storage may be unavailable; the modules still work. */
    }
  }

  function readSnapshot(key) {
    try {
      var raw = sessionStorage.getItem(STORE_PREFIX + key);
      if (!raw) {
        return null;
      }
      var parsed = JSON.parse(raw);
      if (
        !parsed ||
        typeof parsed !== 'object' ||
        !parsed.result ||
        typeof parsed.result !== 'object'
      ) {
        return null;
      }
      return parsed;
    } catch (error) {
      return null;
    }
  }

  function clearSnapshot(key) {
    try {
      sessionStorage.removeItem(STORE_PREFIX + key);
    } catch (error) {
      /* ignore */
    }
  }

  function summarize(key, result) {
    if (key === 'url') {
      var label = result.label || 'Unknown';
      return { text: label, tone: toneFor(label) };
    }
    if (key === 'brand') {
      var brandTone = toneFor(result.result);
      if (typeof result.score === 'number') {
        return {
          text: 'Similarity ' + result.score + ' \u00b7 ' + (result.result || 'Unknown'),
          tone: brandTone
        };
      }
      return { text: result.result || 'Unknown', tone: brandTone };
    }
    var score = typeof result.score === 'number' ? result.score : null;
    var level = result.risk_level || result.result || 'Unknown';
    return {
      text: (score !== null ? 'Score ' + score + ' \u00b7 ' : '') + level,
      tone: toneFor(level)
    };
  }

  /* ---------------------------------------------------------------- */
  /* File validation                                                  */
  /* ---------------------------------------------------------------- */

  function validateImageFile(file) {
    if (!file) {
      return 'Choose a PNG, JPG or JPEG image to analyze.';
    }
    var type = (file.type || '').toLowerCase();
    var ext = (file.name.split('.').pop() || '').toLowerCase();
    var okType = type === 'image/png' || type === 'image/jpeg';
    var okExt = ext === 'png' || ext === 'jpg' || ext === 'jpeg';
    if (!okType && !okExt) {
      return 'Unsupported file type. Upload a PNG, JPG or JPEG image.';
    }
    if (file.size > MAX_IMAGE_BYTES) {
      return 'Image is too large. The maximum size is 5 MB.';
    }
    return null;
  }

  function validateHtmlFile(file) {
    if (!file) {
      return 'Choose an .html or .htm file to analyze.';
    }
    var ext = (file.name.split('.').pop() || '').toLowerCase();
    if (ext !== 'html' && ext !== 'htm') {
      return 'Unsupported file type. Upload an .html or .htm file.';
    }
    if (file.size > MAX_HTML_BYTES) {
      return 'HTML file is too large. The maximum size is 2 MB.';
    }
    return null;
  }

  function bindFileInput(inputId, nameId) {
    var input = byId(inputId);
    var name = byId(nameId);
    if (!input || !name) {
      return;
    }
    input.addEventListener('change', function () {
      var file = input.files && input.files[0];
      name.textContent = file ? file.name + ' \u00b7 ' + formatBytes(file.size) : '';
    });
  }

  /* ---------------------------------------------------------------- */
  /* Module: New Analysis hub                                         */
  /* ---------------------------------------------------------------- */

  function initHub() {
    var nodes = document.querySelectorAll('[data-module-status]');
    for (var i = 0; i < nodes.length; i += 1) {
      var node = nodes[i];
      var key = node.getAttribute('data-module-status');

      if (key === 'combined') {
        var ready = false;
        for (var k = 0; k < MODULE_KEYS.length; k += 1) {
          if (readSnapshot(MODULE_KEYS[k])) {
            ready = true;
            break;
          }
        }
        if (ready) {
          node.textContent = 'Ready to assess';
          node.className = 'module-status is-ready';
        }
        continue;
      }

      var snapshot = readSnapshot(key);
      if (!snapshot) {
        continue;
      }
      var info = summarize(key, snapshot.result);
      node.textContent = info.text;
      node.className = 'module-status ' + statusClass(info.tone);
    }
  }

  /* ---------------------------------------------------------------- */
  /* Module: URL Analysis                                             */
  /* ---------------------------------------------------------------- */

  function renderUrlResult(container, data) {
    var known = data.label === 'Phishing' || data.label === 'Legitimate';
    var extras = [];
    if (data.warning) {
      extras.push(makeAlertNode('warning', data.warning));
    }
    if (data.error) {
      extras.push(makeAlertNode('error', data.error));
    }

    renderResult(
      container,
      resultCard({
        kicker: 'URL Analysis',
        title: known ? 'URL classification' : 'URL not classified',
        level: data.label || 'Unknown',
        tone: toneFor(data.label),
        meta: [
          { label: 'Classification', value: data.label || 'Unknown' },
          {
            label: 'Prediction value',
            value:
              data.prediction === 0 ? '0 (Phishing)' : data.prediction === 1 ? '1 (Legitimate)' : null
          },
          { label: 'Model', value: 'Local Random Forest' },
          { label: 'Network access', value: 'None \u2014 URL not visited' }
        ],
        recommendations: known ? guidanceFor(data.label) : [],
        extra: extras,
        note:
          'The URL model returns a binary classification. The Combined Risk ' +
          'Assessment converts it to a risk value (Phishing \u2248 90, Legitimate \u2248 5).'
      })
    );
  }

  function initUrl() {
    var form = byId('url-form');
    if (!form) {
      return;
    }
    var input = byId('url-input');
    var error = byId('url-error');
    var button = byId('url-submit');
    var result = byId('url-result');

    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      hideAlert(error);
      var value = input.value.trim();
      if (!value) {
        showAlert(error, 'Enter a URL to analyze.', 'error');
        input.focus();
        return;
      }
      setBusy(button, true);
      result.setAttribute('aria-busy', 'true');
      try {
        var data = await requestJSON(form.dataset.api || '/predict', { url: value });
        renderUrlResult(result, data);
        saveSnapshot('url', {
          label: data.label,
          prediction: data.prediction,
          warning: data.warning
        });
      } catch (failure) {
        showAlert(error, failure.message, 'error');
      } finally {
        setBusy(button, false);
        result.setAttribute('aria-busy', 'false');
      }
    });
  }

  /* ---------------------------------------------------------------- */
  /* Module: Text Analysis                                            */
  /* ---------------------------------------------------------------- */

  function renderTextResult(container, data, length) {
    renderResult(
      container,
      resultCard({
        kicker: 'Text Analysis',
        title: 'Message risk score',
        level: data.result || 'Unknown',
        tone: toneFor(data.result),
        score: typeof data.score === 'number' ? data.score : null,
        scoreTone: toneFor(data.result),
        meta: [
          { label: 'Analysis type', value: 'Local heuristic rules' },
          { label: 'Characters analyzed', value: length },
          { label: 'Indicators matched', value: (data.reasons || []).length }
        ],
        reasons: data.reasons || [],
        recommendations: guidanceFor(data.result),
        note:
          'This detector is heuristic. A low score does not guarantee that the ' +
          'message is safe.'
      })
    );
  }

  function initText() {
    var form = byId('text-form');
    if (!form) {
      return;
    }
    var input = byId('text-input');
    var count = byId('text-count');
    var error = byId('text-error');
    var button = byId('text-submit');
    var result = byId('text-result');

    if (input && count) {
      input.addEventListener('input', function () {
        count.textContent = input.value.length + ' characters';
      });
    }

    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      hideAlert(error);
      var value = input.value.trim();
      if (!value) {
        showAlert(error, 'Paste a message to analyze.', 'error');
        input.focus();
        return;
      }
      setBusy(button, true);
      result.setAttribute('aria-busy', 'true');
      try {
        var data = await requestJSON(form.dataset.api || '/detect-text', { text: value });
        renderTextResult(result, data, value.length);
        saveSnapshot('text', {
          score: data.score,
          result: data.result,
          reasons: data.reasons || []
        });
      } catch (failure) {
        showAlert(error, failure.message, 'error');
      } finally {
        setBusy(button, false);
        result.setAttribute('aria-busy', 'false');
      }
    });
  }

  /* ---------------------------------------------------------------- */
  /* Module: OCR Analysis                                             */
  /* ---------------------------------------------------------------- */

  function buildExtract(text) {
    var wrap = make('div');
    if (text) {
      wrap.appendChild(make('pre', 'text-extract', text));
    } else {
      wrap.appendChild(
        make('p', 'result-note', 'No readable text was found in the image.')
      );
    }
    wrap.appendChild(
      make('p', 'extract-note', 'Displayed in this tab only \u2014 never stored.')
    );
    return wrap;
  }

  function renderOcrResult(container, data) {
    var text = typeof data.extracted_text === 'string' ? data.extracted_text : '';
    renderResult(
      container,
      resultCard({
        kicker: 'OCR Analysis',
        title: 'Extracted text risk score',
        level: data.result || 'Unknown',
        tone: toneFor(data.result),
        score: typeof data.score === 'number' ? data.score : null,
        scoreTone: toneFor(data.result),
        meta: [
          { label: 'Extracted characters', value: text.length },
          { label: 'OCR engine', value: 'Tesseract (local)' },
          { label: 'Scoring rules', value: 'Same as Text Analysis' }
        ],
        reasons: data.reasons || [],
        recommendations: guidanceFor(data.result),
        extra: [section('Extracted text', buildExtract(text))],
        note: 'OCR text is shown only in this browser tab and is never saved.'
      })
    );
  }

  function initOcr() {
    var form = byId('ocr-form');
    if (!form) {
      return;
    }
    var input = byId('ocr-file');
    var error = byId('ocr-error');
    var button = byId('ocr-submit');
    var result = byId('ocr-result');

    bindFileInput('ocr-file', 'ocr-file-name');

    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      hideAlert(error);
      var file = input.files && input.files[0];
      var problem = validateImageFile(file);
      if (problem) {
        showAlert(error, problem, 'error');
        return;
      }
      var formData = new FormData();
      formData.append('image', file);

      setBusy(button, true);
      result.setAttribute('aria-busy', 'true');
      try {
        var data = await requestForm(form.dataset.api || '/analyze-image', formData);
        renderOcrResult(result, data);
        saveSnapshot('ocr', {
          score: data.score,
          result: data.result,
          reasons: data.reasons || []
        });
      } catch (failure) {
        showAlert(error, failure.message, 'error');
      } finally {
        setBusy(button, false);
        result.setAttribute('aria-busy', 'false');
      }
    });
  }

  /* ---------------------------------------------------------------- */
  /* Module: Image & Brand Analysis                                   */
  /* ---------------------------------------------------------------- */

  function matchChips(matches) {
    var row = make('div', 'chip-row');
    var limit = Math.min(matches.length, 8);
    for (var i = 0; i < limit; i += 1) {
      var match = matches[i] || {};
      var chip = make('span', 'chip' + (i === 0 ? ' is-info' : ''));
      chip.appendChild(make('strong', null, formatValue(match.score)));
      chip.appendChild(make('span', null, match.brand || 'unnamed'));
      row.appendChild(chip);
    }
    if (matches.length > limit) {
      row.appendChild(make('span', 'chip', '+' + (matches.length - limit) + ' more'));
    }
    return row;
  }

  function renderBrandResult(container, data) {
    var score = typeof data.score === 'number' ? data.score : null;
    var extras = [];
    if (data.references_checked === 0) {
      extras.push(
        makeAlertNode(
          'info',
          'No reference logos are installed yet. Add PNG/JPG files to ' +
            'phishing/brand_references/ to enable similarity scoring.'
        )
      );
    } else if (data.matches && data.matches.length) {
      extras.push(section('Ranked matches', matchChips(data.matches)));
    }
    if (data.warning) {
      extras.push(makeAlertNode('warning', data.warning));
    }

    renderResult(
      container,
      resultCard({
        kicker: 'Image & Brand Analysis',
        title: 'Logo similarity',
        level: data.result || 'Unknown',
        tone: toneFor(data.result),
        score: score,
        scoreTone: 'info',
        meta: [
          { label: 'Best match', value: data.best_match || null },
          {
            label: 'References checked',
            value: data.references_checked === null || data.references_checked === undefined
              ? null
              : data.references_checked
          },
          { label: 'Similarity', value: score === null ? null : score + ' / 100' }
        ],
        extra: extras,
        note:
          'Similarity compares visual appearance only and is supporting evidence, ' +
          'never proof of authenticity or phishing.'
      })
    );
  }

  function initBrand() {
    var form = byId('brand-form');
    if (!form) {
      return;
    }
    var input = byId('brand-file');
    var error = byId('brand-error');
    var button = byId('brand-submit');
    var result = byId('brand-result');

    bindFileInput('brand-file', 'brand-file-name');

    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      hideAlert(error);
      var file = input.files && input.files[0];
      var problem = validateImageFile(file);
      if (problem) {
        showAlert(error, problem, 'error');
        return;
      }
      var formData = new FormData();
      formData.append('image', file);

      setBusy(button, true);
      result.setAttribute('aria-busy', 'true');
      try {
        var data = await requestForm(form.dataset.api || '/analyze-brand', formData);
        renderBrandResult(result, data);
        saveSnapshot('brand', {
          result: data.result,
          score: data.score,
          best_match: data.best_match,
          references_checked: data.references_checked,
          matches: data.matches || [],
          warning: data.warning
        });
      } catch (failure) {
        showAlert(error, failure.message, 'error');
      } finally {
        setBusy(button, false);
        result.setAttribute('aria-busy', 'false');
      }
    });
  }

  /* ---------------------------------------------------------------- */
  /* Module: Login Form Analysis                                      */
  /* ---------------------------------------------------------------- */

  function fieldChips(fields) {
    var row = make('div', 'chip-row');
    var order = ['password', 'email', 'username', 'pin', 'otp'];
    var found = 0;
    order.forEach(function (key) {
      var count = fields && typeof fields[key] === 'number' ? fields[key] : 0;
      if (count > 0) {
        found += 1;
        var chip = make('span', 'chip');
        chip.appendChild(make('strong', null, String(count)));
        chip.appendChild(make('span', null, key === 'otp' ? 'OTP / code' : key));
        row.appendChild(chip);
      }
    });
    if (!found) {
      row.appendChild(make('span', 'chip', 'No credential fields'));
    }
    return row;
  }

  function renderLoginResult(container, data) {
    renderResult(
      container,
      resultCard({
        kicker: 'Login Form Analysis',
        title: 'Form risk score',
        level: data.risk_level || 'Unknown',
        tone: toneFor(data.risk_level),
        score: typeof data.score === 'number' ? data.score : null,
        scoreTone: toneFor(data.risk_level),
        meta: [
          { label: 'Forms found', value: data.forms_found },
          { label: 'Analysis type', value: 'Local HTML structure rules' }
        ],
        reasons: data.reasons || [],
        recommendations: guidanceFor(data.risk_level),
        extra: [section('Detected fields', fieldChips(data.fields))],
        note:
          'Forms are never submitted and input values are not read \u2014 only field ' +
          'names and structure are inspected.'
      })
    );
  }

  function initLogin() {
    var pasteForm = byId('login-paste-form');
    if (!pasteForm) {
      return;
    }
    var textarea = byId('login-html');
    var count = byId('login-count');
    var pasteError = byId('login-paste-error');
    var pasteButton = byId('login-paste-submit');

    var uploadForm = byId('login-upload-form');
    var uploadInput = byId('login-file');
    var uploadError = byId('login-upload-error');
    var uploadButton = byId('login-upload-submit');

    var result = byId('login-result');

    var tabs = [byId('tab-paste'), byId('tab-upload')];
    var panels = [byId('panel-paste'), byId('panel-upload')];
    if (tabs[0] && tabs[1] && panels[0] && panels[1]) {
      var selectTab = function (index) {
        tabs.forEach(function (tab, i) {
          var on = i === index;
          tab.setAttribute('aria-selected', on ? 'true' : 'false');
          tab.tabIndex = on ? 0 : -1;
        });
        panels.forEach(function (panel, i) {
          panel.hidden = i !== index;
        });
      };
      tabs.forEach(function (tab, index) {
        tab.addEventListener('click', function () {
          selectTab(index);
        });
        tab.addEventListener('keydown', function (event) {
          if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
            event.preventDefault();
            var next = index === 0 ? 1 : 0;
            selectTab(next);
            tabs[next].focus();
          }
        });
      });
    }

    if (textarea && count) {
      textarea.addEventListener('input', function () {
        count.textContent = textarea.value.length + ' characters';
      });
    }

    bindFileInput('login-file', 'login-file-name');

    var finish = function (data) {
      renderLoginResult(result, data);
      saveSnapshot('login_form', {
        score: data.score,
        risk_level: data.risk_level,
        forms_found: data.forms_found,
        fields: data.fields || {},
        reasons: data.reasons || []
      });
    };

    pasteForm.addEventListener('submit', async function (event) {
      event.preventDefault();
      hideAlert(pasteError);
      var value = textarea.value.trim();
      if (!value) {
        showAlert(pasteError, 'Paste the HTML source to analyze.', 'error');
        textarea.focus();
        return;
      }
      setBusy(pasteButton, true);
      result.setAttribute('aria-busy', 'true');
      try {
        var data = await requestJSON(pasteForm.dataset.api || '/analyze-login-form', {
          html: value
        });
        finish(data);
      } catch (failure) {
        showAlert(pasteError, failure.message, 'error');
      } finally {
        setBusy(pasteButton, false);
        result.setAttribute('aria-busy', 'false');
      }
    });

    if (uploadForm) {
      uploadForm.addEventListener('submit', async function (event) {
        event.preventDefault();
        hideAlert(uploadError);
        var file = uploadInput.files && uploadInput.files[0];
        var problem = validateHtmlFile(file);
        if (problem) {
          showAlert(uploadError, problem, 'error');
          return;
        }
        var formData = new FormData();
        formData.append('file', file);

        setBusy(uploadButton, true);
        result.setAttribute('aria-busy', 'true');
        try {
          var data = await requestForm(
            uploadForm.dataset.api || '/analyze-login-form',
            formData
          );
          finish(data);
        } catch (failure) {
          showAlert(uploadError, failure.message, 'error');
        } finally {
          setBusy(uploadButton, false);
          result.setAttribute('aria-busy', 'false');
        }
      });
    }
  }

  /* ---------------------------------------------------------------- */
  /* Module: Combined Risk Assessment                                 */
  /* ---------------------------------------------------------------- */

  function moduleRow(key, snapshot, refresh) {
    var row = make('div', 'module-row');
    var dot = make('span', 'status-dot');
    var main = make('div', 'module-row-main');
    main.appendChild(make('p', 'module-row-title', MODULE_LABELS[key]));
    var meta = make('p', 'module-row-meta');
    var actions = make('div', 'module-row-actions');

    if (snapshot) {
      var info = summarize(key, snapshot.result);
      dot.className = 'status-dot ' + statusClass(info.tone);
      meta.textContent = info.text + ' \u00b7 saved ' + formatTime(snapshot.savedAt);
      var open = make('a', 'mini-link', 'Open');
      open.href = MODULE_LINKS[key];
      var clear = make('button', 'mini-link is-danger', 'Clear');
      clear.type = 'button';
      clear.addEventListener('click', function () {
        clearSnapshot(key);
        refresh();
      });
      actions.appendChild(open);
      actions.appendChild(clear);
    } else {
      meta.textContent = 'Not analyzed in this session';
      var run = make('a', 'mini-link', 'Run module');
      run.href = MODULE_LINKS[key];
      actions.appendChild(run);
    }

    main.appendChild(meta);
    row.appendChild(dot);
    row.appendChild(main);
    row.appendChild(actions);
    return row;
  }

  function moduleTable(modules) {
    var wrap = make('div', 'table-wrap');
    var table = make('table', 'data-table compact-table');
    var thead = make('thead');
    var headRow = make('tr');
    ['Module', 'Status', 'Score', 'Summary'].forEach(function (heading) {
      var th = make('th', null, heading);
      th.scope = 'col';
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = make('tbody');
    MODULE_KEYS.forEach(function (key) {
      var info = modules[key] || {};
      var row = make('tr');
      row.appendChild(make('td', null, MODULE_LABELS[key]));

      var statusCell = make('td');
      var statusText = info.available
        ? 'Analyzed'
        : info.status === 'inconclusive'
        ? 'Inconclusive'
        : 'Not analyzed';
      statusCell.appendChild(
        make('span', 'table-status' + (info.available ? ' is-ready' : ''), statusText)
      );
      row.appendChild(statusCell);

      row.appendChild(
        make(
          'td',
          'table-score',
          info.available && typeof info.risk_score === 'number'
            ? String(info.risk_score)
            : '\u2014'
        )
      );
      row.appendChild(make('td', null, info.summary || '\u2014'));
      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  function weightDetails(weights) {
    var details = make('details', 'weight-details');
    details.appendChild(make('summary', null, 'How this score is calculated'));
    var rows = make('div', 'weight-rows');

    var addRow = function (label, value) {
      var row = make('div', 'weight-row');
      row.appendChild(make('span', null, label));
      row.appendChild(make('span', null, value));
      rows.appendChild(row);
    };

    addRow('URL Analysis weight', percent(weights.url));
    addRow('Text or OCR weight', percent(weights.text_or_ocr));
    addRow('Login Form weight', percent(weights.login_form));
    addRow(
      'Brand support cap',
      '+ ' + formatValue(weights.brand_support_max_points) + ' points'
    );

    if (weights.note) {
      rows.appendChild(make('p', 'weight-note', weights.note));
    }
    details.appendChild(rows);
    return details;
  }

  function renderCombinedResult(container, data) {
    var tone = toneFor(data.risk_level);
    var modules = data.modules || {};
    var analyzed = 0;
    MODULE_KEYS.forEach(function (key) {
      if (modules[key] && modules[key].available) {
        analyzed += 1;
      }
    });

    var labelList = function (keys) {
      return (keys || [])
        .map(function (key) {
          return MODULE_LABELS[key] || key;
        })
        .join(', ');
    };

    var missing = labelList(data.missing_modules);
    var inconclusive = labelList(data.inconclusive_modules);

    var extras = [section('Module breakdown', moduleTable(modules))];
    if (data.weights) {
      extras.push(weightDetails(data.weights));
    }
    if (data.disclaimer) {
      extras.push(makeAlertNode('info', data.disclaimer));
    }

    renderResult(
      container,
      resultCard({
        kicker: 'Combined Risk Assessment',
        title: 'Overall phishing risk',
        level: data.risk_level || 'Unknown',
        tone: tone,
        score: typeof data.overall_score === 'number' ? data.overall_score : null,
        scoreTone: tone,
        meta: [
          { label: 'Modules analyzed', value: analyzed + ' of ' + MODULE_KEYS.length },
          { label: 'Missing modules', value: missing || 'None' },
          { label: 'Inconclusive', value: inconclusive || 'None' }
        ],
        reasons: data.reasons || [],
        recommendations: data.recommended_actions || [],
        extra: extras,
        note:
          'Combined scores are heuristic and do not prove that a source is safe ' +
          'or malicious. Always verify through official channels.'
      })
    );
  }

  function initCombined() {
    var container = byId('combined-modules');
    if (!container) {
      return;
    }
    var runButton = byId('combined-run');
    var error = byId('combined-error');
    var result = byId('combined-result');

    var refresh = function () {
      clearNode(container);
      var available = 0;
      MODULE_KEYS.forEach(function (key) {
        var snapshot = readSnapshot(key);
        if (snapshot) {
          available += 1;
        }
        container.appendChild(moduleRow(key, snapshot, refresh));
      });
      if (runButton) {
        runButton.disabled = available === 0;
      }
    };

    if (runButton) {
      runButton.addEventListener('click', async function () {
        hideAlert(error);
        var payload = {};
        var count = 0;
        MODULE_KEYS.forEach(function (key) {
          var snapshot = readSnapshot(key);
          if (snapshot) {
            payload[key] = snapshot.result;
            count += 1;
          }
        });
        if (!count) {
          showAlert(
            error,
            'Run at least one analysis module before the combined assessment.',
            'error'
          );
          return;
        }
        setBusy(runButton, true);
        result.setAttribute('aria-busy', 'true');
        try {
          var data = await requestJSON('/assess-risk', payload);
          renderCombinedResult(result, data);
        } catch (failure) {
          showAlert(error, failure.message, 'error');
        } finally {
          setBusy(runButton, false);
          result.setAttribute('aria-busy', 'false');
        }
      });
    }

    refresh();
  }

  /* ---------------------------------------------------------------- */
  /* Dispatch                                                         */
  /* ---------------------------------------------------------------- */

  document.addEventListener('DOMContentLoaded', function () {
    var page = document.body ? document.body.getAttribute('data-page') : '';

    if (page === 'hub') {
      initHub();
    } else if (page === 'url') {
      initUrl();
    } else if (page === 'text') {
      initText();
    } else if (page === 'ocr') {
      initOcr();
    } else if (page === 'image_brand') {
      initBrand();
    } else if (page === 'login_form') {
      initLogin();
    } else if (page === 'combined') {
      initCombined();
    }
  });
})();

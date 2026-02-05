import asyncio
import base64
import gzip
import zlib
from aiohttp import web
from pyppeteer import launch, errors
from urllib.parse import urlparse, urlunparse, quote
from http.client import responses
import re
import math

MAX_CONCURRENT_PAGES = 6
semaphore = asyncio.Semaphore(MAX_CONCURRENT_PAGES)

# FAST SETTINGS
FAST_BLOCK_RESOURCE_TYPES = set(["image", "media", "font", "stylesheet"])
FAST_BLOCK_THIRD_PARTY = False
FETCH_FULL_RESPONSE = False
NAV_TIMEOUT_MS = 20000
POST_WAIT_MS = 1600
POLL_INTERVAL_MS = 75

# NUMERIC POLICY
ALERT_NUM_MIN = 1
ALERT_NUM_MAX = 100000
NUMERIC_RE = re.compile(r"^\s*\d{1,6}\s*$")
NUMERIC_CALL_RE = re.compile(r"\b(?:alert|confirm|prompt)\s*\(\s*(\d{1,6})\s*\)", re.I)

# ile elementów na event i max łącznie (żeby nie zabić CPU + FP)
MAX_PER_EVENT = 25
MAX_TOTAL = 200

EVENTS_TO_REPLACE = [
    'onafterprint', 'onafterscriptexecute', 'onanimationcancel', 'onanimationend',
    'onanimationiteration', 'onanimationstart', 'onauxclick', 'onbeforecopy', 'onbeforecut',
    'onbeforeinput', 'onbeforeprint', 'onbeforescriptexecute', 'onbeforetoggle', 'onbeforeunload',
    'onbegin', 'onblur', 'oncanplay', 'oncanplaythrough', 'onchange', 'onclick', 'onclose',
    'oncontextmenu', 'oncopy', 'oncuechange', 'oncut', 'ondblclick', 'ondrag', 'ondragend',
    'ondragenter', 'ondragexit', 'ondragleave', 'ondragover', 'ondragstart', 'ondrop',
    'ondurationchange', 'onend', 'onended', 'onerror', 'onfocus', 'onfocusin', 'onfocusout',
    'onformdata', 'onfullscreenchange', 'onhashchange', 'oninput', 'oninvalid', 'onkeydown',
    'onkeypress', 'onkeyup', 'onload', 'onloadeddata', 'onloadedmetadata', 'onloadstart',
    'onmessage', 'onmousedown', 'onmouseenter', 'onmouseleave', 'onmousemove', 'onmouseout',
    'onmouseover', 'onmouseup', 'onmousewheel', 'onmozfullscreenchange', 'onpagehide',
    'onpageshow', 'onpaste', 'onpause', 'onplay', 'onplaying', 'onpointercancel', 'onpointerdown',
    'onpointerenter', 'onpointerleave', 'onpointermove', 'onpointerout', 'onpointerover',
    'onpointerrawupdate', 'onpointerup', 'onpopstate', 'onprogress', 'onratechange', 'onrepeat',
    'onreset', 'onresize', 'onscroll', 'onscrollend', 'onsearch', 'onseeked', 'onseeking',
    'onselect', 'onselectionchange', 'onselectstart', 'onshow', 'onsubmit', 'onsuspend',
    'ontimeupdate', 'ontoggle', 'ontouchend', 'ontouchmove', 'ontouchstart', 'ontransitioncancel',
    'ontransitionend', 'ontransitionrun', 'ontransitionstart', 'onunhandledrejection', 'onunload',
    'onvolumechange', 'onwebkitanimationend', 'onwebkitanimationiteration', 'onwebkitanimationstart',
    'onwebkitmouseforcechanged', 'onwebkitmouseforcedown', 'onwebkitmouseforceup',
    'onwebkitmouseforcewillbegin', 'onwebkitplaybacktargetavailabilitychanged', 'onwebkittransitionend',
    'onwebkitwillrevealbottom', 'onwheel'
]

browser = None
BROWSER_HTTP2_DISABLED = False

ALERT_HOOK_JS = r"""
() => {
  if (!window.__ei) window.__ei = {};
  window.__ei.alerted = false;
  window.__ei.alerts = window.__ei.alerts || [];

  const makeWrapper = (name) => {
    const orig = window[name];
    const wrapped = function(...args) {
      try {
        window.__ei.alerted = true;
        window.__ei.alerts.push({name, args: args.map(a => String(a))});
      } catch(e) {}
      try { return orig.apply(this, args); } catch(e) { return undefined; }
    };
    try {
      Object.defineProperty(window, name, {
        value: wrapped, writable: false, configurable: false, enumerable: true
      });
    } catch(e) {
      try { window[name] = wrapped; } catch(e2) {}
    }
  };

  makeWrapper('alert');
  makeWrapper('confirm');
  makeWrapper('prompt');
}
"""

# Zbieramy kandydatów: elementy z inline handlerami, które zawierają alert/confirm/prompt(num)
# + minimalne dane o nich (path i event)
COLLECT_CANDIDATES_JS = r"""
(events, maxPerEvent, maxTotal, minN, maxN) => {
  const re = /\b(?:alert|confirm|prompt)\s*\(\s*(\d{1,6})\s*\)/i;

  function getNum(handler) {
    try {
      if (!handler) return null;
      const m = String(handler).match(re);
      if (!m) return null;
      const n = parseInt(m[1], 10);
      if (!(n >= minN && n <= maxN)) return null;
      return n;
    } catch(e) { return null; }
  }

  function isVisible(el) {
    try {
      const s = getComputedStyle(el);
      if (!s) return false;
      if (s.display === 'none' || s.visibility === 'hidden') return false;
      const r = el.getBoundingClientRect();
      if (!r || r.width < 2 || r.height < 2) return false;
      // chociaż częściowo w viewport
      if (r.bottom < 0 || r.right < 0) return false;
      return true;
    } catch(e) { return false; }
  }

  // prosta “ścieżka” selektora (nie idealna, ale wystarczy żeby znaleźć element drugi raz)
  function cssPath(el) {
    try {
      if (!el || !el.nodeType || el.nodeType !== 1) return null;
      const parts = [];
      let cur = el;
      let depth = 0;
      while (cur && depth < 6) {
        let p = cur.tagName.toLowerCase();
        if (cur.id) {
          p += '#' + CSS.escape(cur.id);
          parts.unshift(p);
          break;
        } else {
          // nth-of-type
          let idx = 1;
          let sib = cur;
          while ((sib = sib.previousElementSibling)) {
            if (sib.tagName === cur.tagName) idx++;
          }
          p += `:nth-of-type(${idx})`;
          parts.unshift(p);
        }
        cur = cur.parentElement;
        depth++;
      }
      return parts.join(' > ');
    } catch(e) { return null; }
  }

  const out = [];
  let total = 0;

  for (const ev of events) {
    if (total >= maxTotal) break;

    let nodes = [];
    try { nodes = Array.from(document.querySelectorAll('[' + ev + ']')); } catch(e) { nodes = []; }

    let cnt = 0;
    for (const el of nodes) {
      if (total >= maxTotal) break;
      if (cnt >= maxPerEvent) break;

      let handler = null;
      try { handler = el.getAttribute(ev); } catch(e) { handler = null; }
      const n = getNum(handler);
      if (n === null) continue;

      // ucinamy FP: tylko widoczne (po scrollu jeszcze raz sprawdzimy w Python)
      if (!isVisible(el)) continue;

      const sel = cssPath(el);
      if (!sel) continue;

      out.push({ev: ev.toLowerCase(), sel: sel, n: n, tag: (el.tagName||'').toLowerCase()});
      cnt++;
      total++;
    }
  }

  return out;
}
"""

def filter_headers_for_browser(in_headers: dict) -> dict:
    banned = {
        'host', 'content-length',
        'connection', 'proxy-connection', 'keep-alive', 'upgrade',
        'transfer-encoding', 'te', 'trailer',
        'accept-encoding',
    }
    out = {}
    for k, v in (in_headers or {}).items():
        if not k:
            continue
        lk = k.lower().strip()
        if lk.startswith(':'):
            continue
        if lk in banned:
            continue
        if v is None:
            continue
        out[k] = str(v)
    return out

def normalize_and_encode_fragment(fragment: str) -> str:
    if not fragment:
        return ''
    fragment = fragment.strip()
    if fragment.startswith('#'):
        fragment = fragment[1:]
    return quote(fragment, safe="%")

def extract_numeric_hits(alerts):
    vals = []
    if not alerts:
        return False, vals
    for a in alerts:
        args = a.get("args") or []
        for s in args:
            if s is None:
                continue
            ss = str(s)
            if NUMERIC_RE.match(ss):
                try:
                    n = int(ss.strip())
                    if ALERT_NUM_MIN <= n <= ALERT_NUM_MAX:
                        vals.append(n)
                except Exception:
                    pass
    return (len(vals) > 0), sorted(set(vals))

async def create_browser(disable_http2=False):
    args = [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-blink-features=AutomationControlled',
        '--disable-infobars',
        '--disable-dev-shm-usage',
        '--disable-extensions',
        '--disable-gpu',
        '--window-size=1280,720',
        '--disable-features=VizDisplayCompositor',
        '--disable-quic',
        '--mute-audio',
        '--disable-background-networking',
        '--disable-background-timer-throttling',
        '--disable-renderer-backgrounding',
        '--disable-default-apps',
        '--no-first-run',
        '--no-default-browser-check',
    ]
    if disable_http2:
        args.append('--disable-http2')

    print("Tworzenie przeglądarki... disable_http2={}".format(disable_http2))
    return await launch(headless=True, ignoreHTTPSErrors=True, args=args)

async def ensure_browser():
    global browser
    if not browser:
        browser = await create_browser(disable_http2=BROWSER_HTTP2_DISABLED)

async def restart_browser(disable_http2):
    global browser, BROWSER_HTTP2_DISABLED
    BROWSER_HTTP2_DISABLED = disable_http2
    try:
        if browser:
            await browser.close()
    except Exception:
        pass
    browser = await create_browser(disable_http2=disable_http2)

async def poll_alert(page, deadline_ms):
    end = asyncio.get_event_loop().time() + (deadline_ms / 1000.0)
    while asyncio.get_event_loop().time() < end:
        try:
            if await page.evaluate("() => !!(window.__ei && window.__ei.alerted)"):
                return True
        except Exception:
            pass
        await asyncio.sleep(POLL_INTERVAL_MS / 1000.0)
    return False

async def force_resize(page):
    try:
        vp = None
        try:
            vp = await page.viewport()
        except Exception:
            vp = None

        width = 1280
        height = 720
        if isinstance(vp, dict):
            width = int(vp.get("width") or width)
            height = int(vp.get("height") or height)

        await page.setViewport({"width": width + 20, "height": height})
        await asyncio.sleep(0.02)
        await page.setViewport({"width": width, "height": height})
        await asyncio.sleep(0.02)

        # dodatkowo dispatch
        await page.evaluate("""() => {
            try { window.dispatchEvent(new Event('resize')); } catch(e) {}
            try { window.dispatchEvent(new UIEvent('resize')); } catch(e) {}
        }""")
    except Exception:
        pass

async def get_alerts_from_frames(page):
    all_alerts = []
    try:
        main_alerts = await page.evaluate("() => (window.__ei && window.__ei.alerts) ? window.__ei.alerts : []")
        if isinstance(main_alerts, list):
            all_alerts.extend(main_alerts)
    except Exception:
        pass

    try:
        for fr in page.frames:
            try:
                fr_alerts = await fr.evaluate("() => (window.__ei && window.__ei.alerts) ? window.__ei.alerts : []")
                if isinstance(fr_alerts, list) and fr_alerts:
                    all_alerts.extend(fr_alerts)
            except Exception:
                continue
    except Exception:
        pass

    # uniq
    try:
        seen = set()
        uniq = []
        for a in all_alerts:
            key = repr(a)
            if key in seen:
                continue
            seen.add(key)
            uniq.append(a)
        return uniq
    except Exception:
        return all_alerts

# --- REAL INPUT (CDP) helpers ---

async def cdp_mouse_move(page, x, y, steps=6):
    # ruch po linii (żeby był “ludzki”)
    try:
        start = page._mouse._x, page._mouse._y  # internal
    except Exception:
        start = (0, 0)
    sx, sy = start
    for i in range(1, steps + 1):
        nx = sx + (x - sx) * (i / float(steps))
        ny = sy + (y - sy) * (i / float(steps))
        try:
            await page._client.send('Input.dispatchMouseEvent', {
                'type': 'mouseMoved',
                'x': float(nx),
                'y': float(ny),
                'button': 'none',
                'modifiers': 0
            })
        except Exception:
            # fallback pyppeteer mouse
            try:
                await page.mouse.move(float(nx), float(ny))
            except Exception:
                pass
        await asyncio.sleep(0.01)

async def cdp_mouse_click(page, x, y):
    try:
        await page._client.send('Input.dispatchMouseEvent', {
            'type': 'mousePressed', 'x': float(x), 'y': float(y),
            'button': 'left', 'clickCount': 1
        })
        await asyncio.sleep(0.01)
        await page._client.send('Input.dispatchMouseEvent', {
            'type': 'mouseReleased', 'x': float(x), 'y': float(y),
            'button': 'left', 'clickCount': 1
        })
    except Exception:
        try:
            await page.mouse.click(float(x), float(y))
        except Exception:
            pass

async def element_center_box(frame, sel):
    # zwraca (x, y, w, h) w viewport coords (frame context -> main viewport)
    js = r"""
    (sel) => {
      const el = document.querySelector(sel);
      if (!el) return null;
      try { el.scrollIntoView({block:'center', inline:'center', behavior:'instant'}); } catch(e) {}
      const r = el.getBoundingClientRect();
      if (!r) return null;
      if (r.width < 2 || r.height < 2) return null;
      // widoczność
      const s = getComputedStyle(el);
      if (s && (s.display === 'none' || s.visibility === 'hidden')) return null;
      // center + clamp
      const cx = Math.max(2, Math.min(window.innerWidth - 2, r.left + (r.width/2)));
      const cy = Math.max(2, Math.min(window.innerHeight - 2, r.top + (r.height/2)));
      return {x: cx, y: cy, w: r.width, h: r.height, left: r.left, top: r.top};
    }
    """
    try:
        box = await frame.evaluate(js, sel)
        return box
    except Exception:
        return None

async def trigger_hover_like_human(page, frame, sel):
    box = await element_center_box(frame, sel)
    if not box:
        return False

    x = float(box["x"])
    y = float(box["y"])
    w = float(box["w"])
    h = float(box["h"])

    # wejście “z zewnątrz” elementu (żeby mouseover odpalił)
    ox = x - min(40.0, max(6.0, w / 2.0 + 6.0))
    oy = y - min(40.0, max(6.0, h / 2.0 + 6.0))

    await cdp_mouse_move(page, ox, oy, steps=6)
    await asyncio.sleep(0.01)
    await cdp_mouse_move(page, x, y, steps=8)

    # jitter w obrębie elementu (mousemove)
    for j in range(5):
        ang = (j / 5.0) * math.pi * 2.0
        jx = x + math.cos(ang) * min(18.0, max(4.0, w/5.0))
        jy = y + math.sin(ang) * min(18.0, max(4.0, h/5.0))
        await cdp_mouse_move(page, jx, jy, steps=4)
        await asyncio.sleep(0.01)

    return True

async def trigger_click_like_human(page, frame, sel):
    box = await element_center_box(frame, sel)
    if not box:
        return False
    x = float(box["x"])
    y = float(box["y"])
    await cdp_mouse_move(page, x, y, steps=6)
    await asyncio.sleep(0.01)
    await cdp_mouse_click(page, x, y)
    return True

async def trigger_focus(frame, sel):
    try:
        await frame.evaluate(r"""
        (sel) => {
          const el = document.querySelector(sel);
          if (!el) return false;
          try { el.scrollIntoView({block:'center', inline:'center', behavior:'instant'}); } catch(e) {}
          try { if (el.focus) el.focus(); } catch(e) {}
          return true;
        }
        """, sel)
        return True
    except Exception:
        return False

async def trigger_img_error(frame, sel):
    # naturalny error: ustaw src na invalid domain
    try:
        return await frame.evaluate(r"""
        (sel) => {
          const el = document.querySelector(sel);
          if (!el) return false;
          if ((el.tagName||'').toLowerCase() !== 'img') return false;
          try { el.scrollIntoView({block:'center', inline:'center', behavior:'instant'}); } catch(e) {}
          try { el.src = 'http://nonexistent.invalid/__ei_' + Math.random().toString(16).slice(2) + '.png'; } catch(e) {}
          return true;
        }
        """, sel)
    except Exception:
        return False

async def trigger_generic_mouse(page, frame, sel):
    # fallback dla wielu eventów: hover + click
    ok1 = await trigger_hover_like_human(page, frame, sel)
    await asyncio.sleep(0.02)
    ok2 = await trigger_click_like_human(page, frame, sel)
    return ok1 or ok2

async def handle(request):
    await ensure_browser()

    method = request.method
    headers = dict(request.headers)
    body = await request.read()

    target = headers.pop('EI-Target', None)
    method_override = headers.pop('EI-Method', None)
    ei_fragment = headers.pop('EI-Fragment', None)

    if method_override:
        method = method_override

    if not target:
        return web.json_response({'error': 'Brak nagłówka EI-Target'}, status=400)

    request_url = str(request.url)
    parsed_request_url = urlparse(request_url)
    target_parsed = urlparse(target)

    raw_fragment = ''
    if ei_fragment:
        raw_fragment = ei_fragment
    elif target_parsed.fragment:
        raw_fragment = target_parsed.fragment

    fragment = normalize_and_encode_fragment(raw_fragment)

    full_url = urlunparse((
        target_parsed.scheme,
        target_parsed.netloc,
        parsed_request_url.path,
        parsed_request_url.params,
        parsed_request_url.query,
        fragment
    ))

    headers = filter_headers_for_browser(headers)
    body_str = body.decode('utf-8', errors='replace')

    try:
        async with semaphore:
            result = await fetch_page(full_url, method, headers, body_str, fragment)
    except Exception as e:
        err = str(e)
        if 'Connection is closed' in err:
            await restart_browser(disable_http2=BROWSER_HTTP2_DISABLED)
            async with semaphore:
                result = await fetch_page(full_url, method, headers, body_str, fragment)
        elif 'ERR_HTTP2_PROTOCOL_ERROR' in err and not BROWSER_HTTP2_DISABLED:
            await restart_browser(disable_http2=True)
            async with semaphore:
                result = await fetch_page(full_url, method, headers, body_str, fragment)
        else:
            return web.json_response({'error': 'Błąd: {}'.format(err)}, status=500)

    if result.get('redirected'):
        return web.json_response({'error': 'Przekierowanie wykryte, przerywamy przetwarzanie'}, status=302)

    result['http2_disabled'] = bool(BROWSER_HTTP2_DISABLED)
    return web.json_response(result, status=200)

async def fetch_page(url, method, headers, body_str, encoded_fragment):
    global browser
    page = await browser.newPage()

    dialog_detected = False
    dialog_numeric_vals = []

    response_data = None
    response_headers = {}
    response_status_line = ''
    response_body = b''

    main_request_id = None
    response_headers_received = asyncio.Event()
    response_body_received = asyncio.Event()

    target_host = urlparse(url).netloc

    async def safe_close():
        try:
            await page.close()
        except Exception:
            pass

    page.setDefaultNavigationTimeout(NAV_TIMEOUT_MS)

    user_agent = (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/94.0.4606.61 Safari/537.36'
    )
    await page.setUserAgent(user_agent)

    await page.evaluateOnNewDocument('''() => {
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
    }''')

    try:
        await page.setBypassCSP(True)
    except Exception:
        pass

    await page.evaluateOnNewDocument(ALERT_HOOK_JS)
    await page.setExtraHTTPHeaders(headers)

    dialog_event = asyncio.Event()

    async def dialog_handler(dialog):
        nonlocal dialog_detected, dialog_numeric_vals
        try:
            dialog_detected = True
            msg = dialog.message or ""
            if NUMERIC_RE.match(msg):
                try:
                    n = int(msg.strip())
                    if ALERT_NUM_MIN <= n <= ALERT_NUM_MAX:
                        dialog_numeric_vals.append(n)
                except Exception:
                    pass
            dialog_event.set()
            await dialog.dismiss()
        except Exception:
            pass

    page.on('dialog', lambda d: asyncio.ensure_future(dialog_handler(d)))

    client = None
    if FETCH_FULL_RESPONSE:
        client = await page.target.createCDPSession()
        await client.send('Network.enable')

        async def on_response_received_extra_info(event):
            nonlocal response_headers
            if main_request_id and event.get('requestId') == main_request_id:
                response_headers = event.get('headers', {}) or {}
                response_headers_received.set()

        async def on_response_received(event):
            nonlocal response_status_line
            if main_request_id and event.get('requestId') == main_request_id:
                resp = event.get('response', {}) or {}
                status = int(resp.get('status', 0) or 0)
                status_text = resp.get('statusText', '') or ''
                protocol = (resp.get('protocol', 'HTTP/1.1') or 'HTTP/1.1')
                if protocol.lower() == 'h2':
                    protocol = 'HTTP/2'
                elif protocol.lower() == 'http/1.1':
                    protocol = 'HTTP/1.1'
                else:
                    protocol = 'HTTP/1.1'
                if not status_text:
                    status_text = responses.get(status, '')
                response_status_line = f"{protocol} {status} {status_text}"

        async def on_loading_finished(event):
            nonlocal response_body
            if main_request_id and event.get('requestId') == main_request_id:
                try:
                    body_response = await client.send('Network.getResponseBody', {'requestId': main_request_id})
                    body = body_response.get('body', '') or ''
                    if body_response.get('base64Encoded'):
                        response_body = base64.b64decode(body)
                    else:
                        response_body = body.encode('utf-8', errors='replace')
                except Exception:
                    response_body = b''
                finally:
                    response_body_received.set()

        client.on('Network.responseReceivedExtraInfo', lambda e: asyncio.ensure_future(on_response_received_extra_info(e)))
        client.on('Network.responseReceived', lambda e: asyncio.ensure_future(on_response_received(e)))
        client.on('Network.loadingFinished', lambda e: asyncio.ensure_future(on_loading_finished(e)))

    # interception: metoda + blokowanie zasobów
    await page.setRequestInterception(True)
    first_request = True

    async def intercept_request(req):
        nonlocal first_request, main_request_id
        try:
            rtype = None
            try:
                rtype = req.resourceType
            except Exception:
                rtype = None

            if rtype and rtype in FAST_BLOCK_RESOURCE_TYPES:
                await req.abort()
                return

            if FAST_BLOCK_THIRD_PARTY:
                try:
                    r_host = urlparse(req.url).netloc
                    if r_host and r_host != target_host:
                        await req.abort()
                        return
                except Exception:
                    pass

            if first_request and req.isNavigationRequest():
                first_request = False
                merged = dict(req.headers)
                for k, v in headers.items():
                    merged[k] = v

                overrides = {'method': method, 'headers': merged}
                if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                    overrides['postData'] = body_str

                await req.continue_(overrides)

                try:
                    main_request_id = req._requestId
                except Exception:
                    main_request_id = None

                try:
                    await page.setRequestInterception(False)
                except Exception:
                    pass
            else:
                await req.continue_()
        except Exception:
            try:
                await req.continue_()
            except Exception:
                pass

    page.on('request', lambda r: asyncio.ensure_future(intercept_request(r)))

    try:
        response = await page.goto(url, waitUntil='domcontentloaded')

        redirected = False
        try:
            if response and response.request and response.request.redirectChain:
                redirected = len(response.request.redirectChain) > 0
        except Exception:
            pass

        # hashchange (jeśli fragment)
        if encoded_fragment:
            try:
                await page.evaluate("""(frag) => {
                    const payload = '#' + frag;
                    location.hash = '#__ei_probe_hash';
                    try { window.dispatchEvent(new HashChangeEvent('hashchange')); } catch(e) {}
                    location.hash = payload;
                    try { window.dispatchEvent(new HashChangeEvent('hashchange')); } catch(e) {}
                }""", encoded_fragment)
            except Exception:
                pass

        # 1) zbierz kandydatów w MAIN frame + iframes
        candidates = []
        try:
            main_c = await page.evaluate(
                COLLECT_CANDIDATES_JS, EVENTS_TO_REPLACE, MAX_PER_EVENT, MAX_TOTAL, ALERT_NUM_MIN, ALERT_NUM_MAX
            )
            if isinstance(main_c, list):
                candidates.append(("main", page.mainFrame, main_c))
        except Exception:
            pass

        try:
            for fr in page.frames:
                if fr == page.mainFrame:
                    continue
                try:
                    fr_c = await fr.evaluate(
                        COLLECT_CANDIDATES_JS, EVENTS_TO_REPLACE, MAX_PER_EVENT, MAX_TOTAL, ALERT_NUM_MIN, ALERT_NUM_MAX
                    )
                    if isinstance(fr_c, list) and fr_c:
                        candidates.append((fr.url or "frame", fr, fr_c))
                except Exception:
                    continue
        except Exception:
            pass

        triggered = []
        # 2) wykonaj realne triggery per event
        for (fname, fr, items) in candidates:
            for it in items:
                ev = (it.get("ev") or "").lower()
                sel = it.get("sel")
                n = it.get("n")
                tag = it.get("tag")
                if not sel or not ev:
                    continue

                # szybka przerwa, żeby nie dławić event loop
                await asyncio.sleep(0.005)

                ok = False
                if ev in ("onmouseover", "onmouseenter", "onmousemove",
                          "onpointerover", "onpointerenter", "onpointermove"):
                    ok = await trigger_hover_like_human(page, fr, sel)

                elif ev in ("onclick", "ondblclick", "onauxclick", "oncontextmenu",
                            "onmousedown", "onmouseup"):
                    # click pipeline
                    ok = await trigger_click_like_human(page, fr, sel)
                    # i dołóż hover, bo czasem handler jest na hover a payload ma click w stringu
                    if not ok:
                        ok = await trigger_hover_like_human(page, fr, sel)

                elif ev in ("onfocus", "onfocusin", "onfocusout", "onblur"):
                    ok = await trigger_focus(fr, sel)

                elif ev in ("onerror",):
                    ok = await trigger_img_error(fr, sel)

                elif ev in ("onresize",):
                    # global
                    await force_resize(page)
                    ok = True

                else:
                    # fallback: hover + click
                    ok = await trigger_generic_mouse(page, fr, sel)

                if ok:
                    triggered.append({"frame": fname, "ev": ev, "sel": sel, "n": n, "tag": tag})

                # jeśli już złapaliśmy alert -> nie mielmy dalej bez sensu
                try:
                    if await page.evaluate("() => !!(window.__ei && window.__ei.alerted)"):
                        break
                except Exception:
                    pass

            # break outer, jeśli alert
            try:
                if await page.evaluate("() => !!(window.__ei && window.__ei.alerted)"):
                    break
            except Exception:
                pass

        # 3) dodatkowo wymuś resize na końcu (często DOM XSS wchodzi dopiero po resize)
        await force_resize(page)

        # 4) poczekaj chwilę na hook
        await poll_alert(page, POST_WAIT_MS)

        # 5) zbierz alerty i odsieć numeric
        alerts = await get_alerts_from_frames(page)
        hook_hit, hook_nums = extract_numeric_hits(alerts)
        dialog_hit = len(dialog_numeric_vals) > 0

        # krótki fallback na dialog event
        if not (hook_hit or dialog_hit):
            try:
                await asyncio.wait_for(dialog_event.wait(), timeout=0.25)
            except asyncio.TimeoutError:
                pass

        numeric_alert_hit = bool(hook_hit or dialog_hit)
        numeric_values = sorted(set((hook_nums or []) + (dialog_numeric_vals or [])))

        # cleanup cookies
        try:
            cookies = await page.cookies()
            if cookies:
                await page.deleteCookie(*cookies)
        except Exception:
            pass

        await safe_close()

        return {
            "alert_detected": numeric_alert_hit,
            "numeric_values": numeric_values,
            "triggered": triggered[:250],  # debug
            "alerts": alerts[:250],        # debug
            "redirected": redirected,
            "response": response_data
        }

    except errors.TimeoutError:
        await safe_close()
        return {"alert_detected": False, "error": "Timeout podczas ładowania strony.", "response": response_data}
    except Exception:
        await safe_close()
        raise

app = web.Application()
app.add_routes([web.route('*', '/{tail:.*}', handle)])

if __name__ == '__main__':
    web.run_app(app, host='localhost', port=7437)

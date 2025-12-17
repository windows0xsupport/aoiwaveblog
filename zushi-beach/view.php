<?php
// view.php — Sessions listing + richer filters/tags + CSV + enhanced player (live details, action sim, live rule matches)
// Fixes:
// - Filters “Toggle” now works (Bootstrap JS included on list view too)
// - Live clock shown in header
// - Items per page control added after Sort
// - Mouse/Scroll/Resize counters in player are accurate (no runaway counts)
// - Sidebar shows more collected client/server fields

$BASE = __DIR__ . '/sessions';
if (!is_dir($BASE))
  @mkdir($BASE, 0775, true);

function h($s)
{
  return htmlspecialchars((string) $s, ENT_QUOTES);
}
function safe($s)
{
  return preg_replace('/[^a-zA-Z0-9_\-\.]/', '_', $s);
}
function meta_file($sid)
{
  global $BASE;
  return $BASE . '/' . safe($sid) . '/meta.json';
}
function list_visits($sid)
{
  $dir = dirname(meta_file($sid));
  if (!is_dir($dir))
    return [];
  $out = [];
  foreach (scandir($dir) as $f) {
    if (!str_ends_with($f, '.ldjson'))
      continue;
    $p = $dir . '/' . $f;
    $out[] = ['file' => $f, 'path' => $p, 'ctime' => filectime($p)];
  }
  usort($out, fn($a, $b) => $a['ctime'] <=> $b['ctime']);
  return $out;
}
function load_meta($sid)
{
  $f = meta_file($sid);
  if (!is_file($f))
    return null;
  return json_decode(@file_get_contents($f), true);
}
function sessions_index()
{
  global $BASE;
  $rows = [];
  foreach (scandir($BASE) as $d) {
    if ($d === '.' || $d === '..' || $d === '_ipcache')
      continue;
    $mf = meta_file($d);
    if (!is_file($mf))
      continue;
    $meta = json_decode(@file_get_contents($mf), true);
    if (!$meta)
      continue;
    $rows[] = ['sid' => $d, 'meta' => $meta, 'mtime' => filemtime($mf)];
  }
  return $rows;
}
function load_settings()
{
  $f = __DIR__ . '/settings.json';
  if (!is_file($f))
    return [];
  $a = json_decode(@file_get_contents($f), true);
  return is_array($a) ? array_values(array_filter($a, 'is_array')) : [];
}

function ua_to_browser_os($ua)
{
  $u = strtolower((string) $ua);
  $isBot = (bool) preg_match('/bot|crawler|spider|preview|fetcher|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegram|bingpreview|curl|wget|python-requests|golang|httpclient|axios|vkshare/i', $u);
  $b = $isBot ? 'Bot' : (str_contains($u, 'edg') ? 'Edge' : (str_contains($u, 'chrome') ? 'Chrome' : (str_contains($u, 'safari') ? 'Safari' : (str_contains($u, 'firefox') ? 'Firefox' : 'Other'))));
  $o = $isBot ? 'Bot' : (str_contains($u, 'windows') ? 'Windows' : (str_contains($u, 'android') ? 'Android' : (str_contains($u, 'iphone') || str_contains($u, 'ipad') ? 'iOS' : (str_contains($u, 'mac os') ? 'macOS' : (str_contains($u, 'linux') ? 'Linux' : 'Other')))));
  return [$b, $o, $isBot];
}
function vpn_heuristic($org, $isp)
{
  $hay = strtolower(trim((string) $org . ' ' . (string) $isp));
  foreach (['nordvpn', 'expressvpn', 'surfshark', 'proton vpn', 'cyberghost', 'cloudflare', 'amazon', 'aws', 'azure', 'microsoft', 'google cloud', 'gcp', 'digitalocean', 'ovh', 'hetzner', 'linode', 'vultr'] as $m) {
    if ($m !== '' && strpos($hay, $m) !== false)
      return $m;
  }
  return '';
}
function is_hosting($org, $isp)
{
  $hay = strtolower(trim((string) $org . ' ' . (string) $isp));
  foreach (['cloudflare', 'amazon', 'aws', 'azure', 'microsoft', 'google cloud', 'gcp', 'digitalocean', 'ovh', 'hetzner', 'linode', 'vultr', 'aliyun', 'alibaba', 'oracle cloud', 'akamai', 'fastly'] as $m) {
    if ($m !== '' && strpos($hay, $m) !== false)
      return true;
  }
  return false;
}
function visit_info($path)
{
  $fh = @fopen($path, 'r');
  if (!$fh)
    return [0, 'server', 0, false, false, false, false, null];
  $ev = 0;
  $lastVis = null;
  $closed = false;
  $lastT = 0;
  $hasClient = false;
  $mouse = false;
  $scrolled = false;
  $resized = false;
  $lastAction = null;
  while (!feof($fh)) {
    $l = fgets($fh);
    if ($l === false)
      break;
    $j = json_decode($l, true);
    if (!$j || !is_array($j))
      continue;
    $ev++;
    $lastT = max($lastT, (float) ($j['t'] ?? 0));
    $type = $j['type'] ?? '';
    if (!in_array($type, ['server_init', 'server_hit', 'noscript_ping'], true))
      $hasClient = true;
    if ($type === 'beforeunload' || $type === 'unload' || $type === 'pagehide')
      $closed = true;
    if ($type === 'visibilitychange')
      $lastVis = $j['data']['visibility'] ?? $lastVis;
    if ($type === 'mousemove')
      $mouse = true;
    if ($type === 'scroll')
      $scrolled = true;
    if ($type === 'resize')
      $resized = true;
    if ($type === 'action_taken')
      $lastAction = ($j['data']['type'] ?? '') ?: $lastAction;
  }
  fclose($fh);
  if (!$hasClient)
    $status = 'server';
  else if ($closed)
    $status = 'closed';
  else if ($lastVis === 'hidden')
    $status = 'idle';
  else
    $status = 'live';
  return [$ev, $status, $lastT, $hasClient, $mouse, $scrolled, $resized, $lastAction];
}

function visit_start_time_from_file($filename)
{
  $base = pathinfo($filename, PATHINFO_FILENAME);
  $ts = (float) $base;
  if ($ts <= 0)
    return $base;
  return date('Y-m-d H:i:s', (int) $ts);
}
function count_events_quick($path, $limit = 500000)
{
  $n = 0;
  $fh = @fopen($path, 'r');
  if (!$fh)
    return 0;
  while (!feof($fh) && $n < $limit) {
    fgets($fh);
    $n++;
  }
  fclose($fh);
  return $n;
}
function ldjson_last_type($path)
{
  $fh = @fopen($path, 'r');
  if (!$fh)
    return '';
  $stat = @fstat($fh);
  $size = (int) ($stat['size'] ?? 0);
  $buf = '';
  $step = 4096;
  $line = '';
  for ($offset = $size; $offset > 0; $offset -= $step) {
    $need = ($offset - $step >= 0) ? $step : $offset;
    fseek($fh, max(0, $offset - $need));
    $chunk = fread($fh, $need);
    $buf = $chunk . $buf;
    $parts = explode("
", $buf);
    for ($i = count($parts) - 1; $i >= 0; $i--) {
      $line = trim($parts[$i]);
      if ($line !== '') {
        fclose($fh);
        $j = json_decode($line, true);
        return $j['type'] ?? '';
      }
    }
    if (strlen($buf) > 1048576)
      $buf = substr($buf, -524288); // keep last 512KB
  }
  fclose($fh);
  return '';
}
function tag_guess_view_source($ua, $hasAnyClient)
{
  if ($hasAnyClient)
    return false;
  $u = strtolower((string) $ua);
  $looksBrowser = (str_contains($u, 'chrome') || str_contains($u, 'firefox') || str_contains($u, 'safari') || str_contains($u, 'edg'));
  $isBot = (bool) preg_match('/bot|crawler|spider|bingpreview|facebookexternalhit|twitterbot|curl|wget|python-requests|httpclient/i', $u);
  return $looksBrowser && !$isBot;
}

// Serve LDJSON for player
if (($_GET['mode'] ?? '') === 'ldjson') {
  $sid = $_GET['sid'] ?? '';
  $vid = $_GET['vid'] ?? '';
  $p = dirname(meta_file($sid)) . '/' . safe($vid) . '.ldjson';
  if (!is_file($p)) {
    header('Content-Type:text/plain');
    http_response_code(404);
    echo "Not found";
    exit;
  }
  header('Content-Type:text/plain; charset=utf-8');
  readfile($p);
  exit;
}

// CSV export
if (($_GET['mode'] ?? '') === 'csv') {
  header('Content-Type: text/csv; charset=utf-8');
  header('Content-Disposition: attachment; filename="sessions_export.csv"');
  $out = fopen('php://output', 'w');
  fputcsv($out, ['session_id', 'visit_id', 'visit_start', 'events', 'status', 'duration_ms', 'url', 'ip', 'countryCode', 'country', 'browser', 'os', 'tz', 'screen_w', 'screen_h', 'viewport_w', 'viewport_h', 'created_at', 'updated_at', 'action_type', 'tags']);
  foreach (sessions_index() as $row) {
    $sid = $row['sid'];
    $m = $row['meta'];
    $mb = $m['meta_from_browser'] ?? [];
    $ipinfo = $m['ip_info'] ?? [];
    $url = $mb['url'] ?? '';
    $ip = $m['ip'] ?? '';
    $tz = $mb['tz'] ?? '';
    $sw = $mb['screen']['w'] ?? '';
    $sh = $mb['screen']['h'] ?? '';
    $vw = $mb['viewport']['w'] ?? '';
    $vh = $mb['viewport']['h'] ?? '';
    $ua = $mb['ua'] ?? '';
    [$b, $o, $isBot] = ua_to_browser_os($ua);
    $cc = $ipinfo['countryCode'] ?? '';
    $cn = $ipinfo['country'] ?? '';
    $act = $m['action_candidate']['type'] ?? '';
    $tagsArr = is_array($m['tags'] ?? null) ? $m['tags'] : [];
    foreach (array_values(array_filter(list_visits($sid), function ($v) {
      return strpos($v['file'], 'sv-') === false; })) as $v) {
      $vid = pathinfo($v['file'], PATHINFO_FILENAME);
      [$ev, $status, $lastT] = visit_info($v['path']);
      fputcsv($out, [$sid, $vid, visit_start_time_from_file($v['file']), $ev, $status, $lastT, $url, $ip, $cc, $cn, $b, $o, $tz, $sw, $sh, $vw, $vh, $m['created_at'] ?? '', $m['updated_at'] ?? '', $act, implode('|', $tagsArr)]);
    }
  }
  fclose($out);
  exit;
}

// Player
if (isset($_GET['play'])) {
  $sid = $_GET['play'];
  $vid = $_GET['vid'] ?? '';
  if (!$vid) {
    $vis = list_visits($sid);
    if ($vis)
      $vid = pathinfo(end($vis)['file'], PATHINFO_FILENAME);
  }
  $m = load_meta($sid) ?: [];
  $url = $m['meta_from_browser']['url'] ?? '';
  $vpw = (int) ($m['meta_from_browser']['viewport']['w'] ?? 1280);
  $vph = (int) ($m['meta_from_browser']['viewport']['h'] ?? 720);
  $ua = $m['meta_from_browser']['ua'] ?? '';
  [$b, $o] = $ua ? ua_to_browser_os($ua) : ['Other', 'Other', false];
  $ip = $m['ip'] ?? '';
  $ipinfo = $m['ip_info'] ?? [];
  $cc = $ipinfo['countryCode'] ?? '';
  $cn = $ipinfo['country'] ?? '';
  $org = $ipinfo['org'] ?? '';
  $isp = $ipinfo['isp'] ?? '';
  $vpn = ($ipinfo['proxy'] ?? false) ? 'Yes' : (vpn_heuristic($org, $isp) ? 'Likely' : 'No');
  $isHosting = is_hosting($org, $isp) ? 'Yes' : 'No';
  $tz = $m['meta_from_browser']['tz'] ?? '';
  $langs = $m['meta_from_browser']['lang'] ?? '';
  $scrW = $m['meta_from_browser']['screen']['w'] ?? '';
  $scrH = $m['meta_from_browser']['screen']['h'] ?? '';
  $referrer = $m['meta_from_browser']['referrer'] ?? '';
  $httpMethod = $m['meta_from_browser']['page_http_method'] ?? ($m['server']['request']['method'] ?? 'GET');

  $serverHeaders = array_filter(($m['server']['request']['headers'] ?? []), fn($k) => true, ARRAY_FILTER_USE_KEY);
  $headerNames = implode(',', array_keys($serverHeaders));
  $cookieNames = '';
  if (isset($m['server']['request']['headers']['HTTP_COOKIE'])) {
    $cookieNames = implode(',', array_keys(array_filter(array_map('trim', array_column(array_map(function ($p) {
      $kv = explode('=', $p, 2);
      return ['k' => trim($kv[0] ?? '')]; }, explode(';', $m['server']['request']['headers']['HTTP_COOKIE'] ?? '')), 'k')))));
  }
  $created = isset($m['created_at']) ? date('Y-m-d H:i:s', strtotime($m['created_at'])) : '';
  $updated = isset($m['updated_at']) ? date('Y-m-d H:i:s', strtotime($m['updated_at'])) : '';
  if (!$sid || !$vid || !is_file(dirname(meta_file($sid)) . '/' . safe($vid) . '.ldjson')) {
    echo "Session or visit not found";
    exit;
  }
  $rules = load_settings();
  ?>
  <!doctype html>
  <html>

  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Replay <?= h($sid) ?> / <?= h($vid) ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      html,
      body {
        height: 100%;
        overflow: hidden;
        background: #f8f9fa
      }

      .page {
        display: flex;
        flex-direction: column;
        height: 100%
      }

      .main {
        flex: 1;
        display: flex;
        gap: 12px;
        padding: 12px;
        min-height: 0
      }

      .sidebar {
        width: 400px;
        min-width: 260px;
        max-width: 540px;
        overflow: auto
      }

      .stage-wrap {
        flex: 1;
        display: flex;
        align-items: center;
        justify-content: center;
        overflow: hidden;
        min-width: 0
      }

      .stage {
        background: #fff;
        transform-origin: top left;
        box-shadow: 0 6px 24px rgba(0, 0, 0, .08);
        position: relative;
        overflow: hidden
      }

      .vp {
        border: 0;
        background: #fff;
        pointer-events: none
      }

      .cursor {
        position: absolute;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        background: rgba(220, 53, 69, .9);
        pointer-events: none;
        transform: translate(-50%, -50%)
      }

      .ripple {
        position: absolute;
        border: 2px solid #0d6efd;
        border-radius: 50%;
        width: 10px;
        height: 10px;
        transform: translate(-50%, -50%);
        opacity: .9
      }

      .controls {
        border-top: 1px solid #dee2e6;
        background: #fff
      }

      .small-mono {
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size: .825rem
      }

      /* .kv .badge{min-width:120px} */
      td {
        word-break: break-all;
        max-width: 50vw;
      }

      .status-badge {
        font-weight: 600
      }

      .rule-chip {
        display: inline-block;
        margin: 2px 4px 0 0
      }

      .kv .row+.row {
        margin-top: .25rem;
      }
    </style>
  </head>

  <body>
    <div class="page">
      <div class="main">
        <div class="card sidebar">
          <div class="card-header d-flex align-items-center justify-content-between">
            <span>Session Details</span>
            <a class="btn btn-sm btn-outline-secondary" type="button" href="./view.php">← Back</a>
          </div>
          <div class="card-body">
            <div class="kv">
              <div class="mb-2"><span class="badge text-bg-secondary">URL</span> <span class="small-mono"
                  id="d_url"><?= h($url) ?></span></div>
              <div class="row">
                <div class="col"><span class="badge text-bg-light border">Session</span> <code><?= h($sid) ?></code></div>
                <div class="col"><span class="badge text-bg-light border">Visit</span> <code><?= h($vid) ?></code></div>
              </div>
              <hr>
              <div class="row">
                <div class="col"><span class="badge text-bg-light border">IP</span> <span id="d_ip"><?= h($ip) ?></span>
                </div>
                <div class="col"><span class="badge text-bg-light border">Country</span> <span
                    id="d_cc"><?= h($cc . ' ' . $cn) ?></span></div>
              </div>
              <div class="row">
                <div class="col"><span class="badge text-bg-light border">Org/ISP</span> <span
                    id="d_org"><?= h(trim($org . ' / ' . $isp)) ?></span></div>
                <div class="col"><span class="badge text-bg-light border">VPN</span> <span
                    id="d_vpn"><?= h($vpn) ?></span></div>
              </div>
              <div class="row">
                <div class="col"><span class="badge text-bg-light border">Hosting</span> <span
                    id="d_host"><?= h($isHosting) ?></span></div>
                <div class="col"><span class="badge text-bg-light border">Method</span> <?= h($httpMethod) ?></div>
              </div>
              <div class="row">
                <div class="col"><span class="badge text-bg-light border">Browser</span> <span
                    id="d_br"><?= h($b) ?></span></div>
                <div class="col"><span class="badge text-bg-light border">OS</span> <span id="d_os"><?= h($o) ?></span>
                </div>
              </div>
              <div class="row">
                <div class="col"><span class="badge text-bg-light border">TZ</span> <span id="d_tz"><?= h($tz) ?></span>
                </div>
                <div class="col"><span class="badge text-bg-light border">Langs</span> <span
                    id="d_langs"><?= h($langs) ?></span></div>
              </div>
              <div class="row">
                <div class="col"><span class="badge text-bg-light border">Viewport</span> <span id="d_vp"><?= (int) $vpw ?>
                    × <?= (int) $vph ?></span></div>
                <div class="col"><span class="badge text-bg-light border">Screen</span> <span id="d_scr"><?= h($scrW) ?> ×
                    <?= h($scrH) ?></span></div>
              </div>
              <div class="row">
                <div class="col"><span class="badge text-bg-light border">Headers</span> <span
                    class="small-mono"><?= h($headerNames) ?></span></div>
              </div>
              <div class="row">
                <div class="col"><span class="badge text-bg-light border">Cookies</span> <span
                    class="small-mono"><?= h($cookieNames) ?></span></div>
              </div>
              <div class="row mt-2">
                <div class="col"><span class="badge text-bg-light border">Created</span> <?= h($created) ?></div>
                <div class="col"><span class="badge text-bg-light border">Updated</span> <span
                    id="d_updated"><?= h($updated) ?></span></div>
              </div>

              <div class="mt-3">
                <span class="badge text-bg-primary">Status</span>
                <span id="d_status" class="badge text-bg-secondary status-badge">—</span>
              </div>
              <div class="mt-2 d-flex gap-2 flex-wrap">
                <span class="badge text-bg-light border">Mouse moved: <span id="c_mouse">0</span></span>
                <span class="badge text-bg-light border">Scrolled: <span id="c_scroll">0</span></span>
                <span class="badge text-bg-light border">Resized: <span id="c_resize">0</span></span>
                <span class="badge text-bg-info">Action taken: <span id="d_action">—</span></span>
              </div>

              <div class="mt-3">
                <span class="badge text-bg-dark">Live Rule Matches</span>
                <div id="liveRules" class="mt-2"></div>
              </div>

              <div class="mt-2"><span class="badge text-bg-primary">Duration</span> <span id="durText">—</span></div>
            </div>
          </div>
        </div>

        <div class="stage-wrap">
          <div id="stage" class="stage" style="width:<?= (int) $vpw ?>px;height:<?= (int) $vph ?>px;">
            <iframe id="vp" class="vp" src="<?= h($url) ?>" style="width:100%;height:100%"></iframe>
            <div id="cursor" class="cursor"></div>
          </div>
        </div>
      </div>

      <div class="controls card rounded-0">
        <div class="card-body">
          <div class="row g-3 align-items-center">
            <div class="col-12 col-md-auto d-flex gap-2">
              <button id="play" class="btn btn-success btn-sm">Play</button>
              <button id="pause" class="btn btn-warning btn-sm">Pause</button>
              <button id="stop" class="btn btn-danger btn-sm">Stop</button>
            </div>
            <div class="col-12 col-md">
              <div><span id="time" class="badge text-bg-light border">00:00 / 00:00 • 0/0</span></div>
              <input id="seek" type="range" min="0" max="1000" step="1" value="0" class="form-range">
            </div>
            <div class="col-12 col-md-3">
              <label for="speed" class="form-label mb-1">Speed <span id="speedLbl" class="text-muted">1.00×</span></label>
              <input id="speed" type="range" min="0.25" max="3" step="0.25" value="1" class="form-range">
            </div>
            <div class="col-12 col-md-3">
              <div class="d-flex align-items-center justify-content-between">
                <label for="scale" class="form-label mb-1">Scale</label>
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" id="autoScale" checked>
                  <label class="form-check-label" for="autoScale">Auto-scale</label>
                </div>
              </div>
              <input id="scale" type="range" min="0.1" max="1.0" step="0.05" value="0.9" class="form-range" disabled>
            </div>
          </div>
        </div>
      </div>
    </div>

    <script>
      // ---------- Embed rules + base context ----------
      const RULES = <?= json_encode(array_map(function ($r) {
        return [
          'id' => $r['id'] ?? '',
          'conditions' => $r['conditions'] ?? [],
          'criteria' => $r['criteria'] ?? [],
          'action' => $r['action'] ?? [],
        ];
      }, $rules), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?>;

      const BASE_CTX = {
        http_method: <?= json_encode($httpMethod) ?>,
        query_params: (function (u) { try { const q = {}; new URL(u, location.href).searchParams.forEach((v, k) => q[k] = v); return q; } catch (_) { return {}; } })(<?= json_encode($url) ?>),
        ip: <?= json_encode($ip) ?>,
        referrer: <?= json_encode($referrer) ?>,
        ua: <?= json_encode($ua) ?>,
        ua_contains: <?= json_encode($ua) ?>,
        browser: <?= json_encode($b) ?>,
        os: <?= json_encode($o) ?>,
        path_regex: (function (u) { try { return new URL(u, location.href).pathname || ''; } catch (_) { return ''; } })(<?= json_encode($url) ?>),
        header_has: <?= json_encode($headerNames) ?>,
        cookie_has: <?= json_encode($cookieNames) ?>,
        ip_country: <?= json_encode($cc) ?>,
        ip_hostname: <?= json_encode($ipinfo['reverse'] ?? '') ?>,
        proxy_ip: <?= json_encode(($ipinfo['proxy'] ?? false) ? 'true' : '') ?>,
        vpn_name: <?= json_encode(vpn_heuristic($org, $isp)) ?>,
        browser_timezone: <?= json_encode($tz) ?>,
        screen_w: <?= json_encode((string) $scrW) ?>,
        screen_h: <?= json_encode((string) $scrH) ?>,
        lang: <?= json_encode($m['meta_from_browser']['lang'] ?? '') ?>,
      };
    </script>

    <script>
      (async () => {
        const SID = <?= json_encode($sid) ?>, VID = <?= json_encode($vid) ?>;
        const dataUrl = <?= json_encode($_SERVER['PHP_SELF']) ?> + "?mode=ldjson&sid=" + encodeURIComponent(SID) + "&vid=" + encodeURIComponent(VID);
        const text = await (await fetch(dataUrl)).text();
        const lines = text.trim() ? text.trim().split(/\n+/).map(l => { try { return JSON.parse(l) } catch { return null } }).filter(Boolean) : [];
        const totalMs = lines.length ? Math.max(...lines.map(e => +e.t || 0)) : 0;
        const totalEvents = lines.length;

        const stage = document.getElementById('stage'), cursor = document.getElementById('cursor');
        const iframe = document.getElementById('vp');
        const seek = document.getElementById('seek'), speed = document.getElementById('speed'), speedLbl = document.getElementById('speedLbl'), timeEl = document.getElementById('time');
        const btnP = document.getElementById('play'), btnPa = document.getElementById('pause'), btnS = document.getElementById('stop'), scale = document.getElementById('scale'), autoScale = document.getElementById('autoScale');
        const durText = document.getElementById('durText');

        // live detail elements
        const dStatus = document.getElementById('d_status');
        const cMouse = document.getElementById('c_mouse');
        const cScroll = document.getElementById('c_scroll');
        const cResize = document.getElementById('c_resize');
        const dAction = document.getElementById('d_action');
        const liveRulesEl = document.getElementById('liveRules');

        seek.max = String(Math.max(1, totalMs));
        durText.textContent = (totalMs ? fmt(totalMs) : '—');

        let playing = false, startWall = 0, pausedAt = 0, raf = 0;
        let lastRenderedT = 0;           // for incremental application
        let appliedIndex = 0;            // index up to which events have been applied
        let mouseCnt = 0, scrollCnt = 0, resizeCnt = 0;
        let lastVis = 'visible', closed = false, lastActionType = '';

        function fmt(ms) { const s = Math.floor(ms / 1000); return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`; }
        function computeAutoScale() {
          const wrap = document.querySelector('.stage-wrap');
          const rect = wrap.getBoundingClientRect();
          const sw = stage.offsetWidth || 1, sh = stage.offsetHeight || 1;
          const scW = Math.max(0.1, Math.min(1, (rect.width - 24) / sw));
          const scH = Math.max(0.1, Math.min(1, (rect.height - 24) / sh));
          return Math.min(scW, scH);
        }
        function applyScale() {
          if (autoScale.checked) {
            const sc = computeAutoScale();
            stage.style.transform = `scale(${sc})`;
            scale.value = sc.toFixed(2);
            scale.setAttribute('disabled', 'disabled');
          } else {
            scale.removeAttribute('disabled');
            const sc = parseFloat(scale.value) || 1;
            stage.style.transform = `scale(${sc})`;
          }
        }
        applyScale();
        window.addEventListener('resize', () => { if (autoScale.checked) applyScale(); });
        speed.addEventListener('input', () => speedLbl.textContent = (+speed.value).toFixed(2) + '×');
        scale.addEventListener('input', () => { if (!autoScale.checked) applyScale(); });

        // simulator bridge
        let simReady = false;
        window.addEventListener('message', (e) => { const msg = e.data || {}; if (msg && msg.__replay && msg.event === 'sim_ready') simReady = true; });
        function postToChild(type, data) { try { iframe.contentWindow.postMessage({ __replay: true, type, data }, '*'); } catch (_) { } }

        function setStatusBadge(status) {
          dStatus.textContent = status.toUpperCase();
          dStatus.className = 'badge status-badge ' + (status === 'live' ? 'text-bg-danger' : status === 'idle' ? 'text-bg-secondary' : status === 'server' ? 'text-bg-light' : 'text-bg-success');
        }

        // ---------- Rule matcher ----------
        function normList(v) {
          if (Array.isArray(v)) return v.map(x => String(x)).filter(Boolean);
          v = String(v ?? '').trim();
          if (!v) return [];
          return v.split(',').map(s => s.trim()).filter(Boolean);
        }
        function opMatch(expect, actual) {
          if (!expect || typeof expect !== 'object' || !('op' in expect)) {
            if (expect === 'is_not_empty') return String(actual || '') !== '';
            if (expect === 'empty') return String(actual || '') === '';
            if (typeof expect === 'string' && expect.startsWith('regex:/') && expect.endsWith('/')) {
              const pat = expect.slice(6, -1); try { return new RegExp(pat, 'i').test(String(actual || '')); } catch { return false; }
            }
            return String(expect) === String(actual ?? '');
          }
          const op = String(expect.op || '').toLowerCase();
          const val = expect.value ?? null;
          const sact = (typeof actual === 'string' || typeof actual === 'number') ? String(actual) : (actual ?? '');
          switch (op) {
            case 'empty': return actual === null || actual === '';
            case 'not_empty': return !(actual === null || actual === '');
            case 'eq': return String(val) === String(sact);
            case 'neq': return String(val) !== String(sact);
            case 'contains': return String(sact).toLowerCase().includes(String(val).toLowerCase());
            case 'not_contains': return !String(sact).toLowerCase().includes(String(val).toLowerCase());
            case 'in': return normList(val).includes(String(sact));
            case 'not_in': return !normList(val).includes(String(sact));
            case 'regex': {
              const pat = String(val || ''); if (!pat) return false;
              try { return new RegExp(pat, 'i').test(String(sact)); } catch { return false; }
            }
            default: return String(val) === String(sact);
          }
        }
        function ruleMatches(rule, ctx) {
          const c = rule?.conditions || {};
          for (const [k, exp] of Object.entries(c)) {
            if (k === 'query_params' && exp && typeof exp === 'object') {
              for (const [name, ve] of Object.entries(exp)) {
                const act = ctx.query_params?.[name] ?? null;
                if (!opMatch(ve, act)) return false;
              }
              continue;
            }
            if (k === 'referrer_contains') {
              const want = exp;
              if (want && typeof want === 'object' && 'op' in want) { if (!opMatch(want, ctx.referrer || '')) return false; }
              else { if (!String(ctx.referrer || '').toLowerCase().includes(String(want).toLowerCase())) return false; }
              continue;
            }
            if (k === 'path_regex') {
              const pat = (exp && typeof exp === 'object') ? (exp.value || '') : exp;
              if (!pat) return false;
              try { if (!(new RegExp(String(pat))).test(String(ctx.path_regex || ''))) return false; } catch { return false; }
              continue;
            }
            if (!opMatch(exp, ctx[k] ?? null)) return false;
          }
          return true;
        }
        function renderLiveRuleMatches(ctx) {
          const matches = RULES.filter(r => ruleMatches(r, ctx));
          if (!matches.length) { liveRulesEl.innerHTML = '<span class="text-muted">No matches</span>'; return; }
          liveRulesEl.innerHTML = matches.map(r => {
            const crit = Array.isArray(r.criteria) ? r.criteria.filter(c => c !== 'Server-Side') : [];
            const hasServer = Array.isArray(r.criteria) && r.criteria.includes('Server-Side');
            const act = r.action?.type || '—';
            const badge = hasServer ? 'text-bg-primary' : 'text-bg-secondary';
            return `<div class="rule-chip">
            <span class="badge ${badge}">#${escapeHtml(r.id || '–')}</span>
            <span class="badge text-bg-info">${escapeHtml(act)}</span>
            ${crit.length ? `<span class="badge text-bg-light border">on: ${crit.map(escapeHtml).join(', ')}</span>` : ''}
          </div>`;
          }).join('');
        }
        function escapeHtml(s) { return String(s).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m])); }

        const ctx = JSON.parse(JSON.stringify(BASE_CTX));

        function renderIncrement(toT) {
          // if seeking backwards, reset and replay from start up to toT
          if (toT < lastRenderedT) {
            appliedIndex = 0;
            lastRenderedT = 0;
            mouseCnt = 0; scrollCnt = 0; resizeCnt = 0;
            lastVis = 'visible'; closed = false; lastActionType = '';
            // clear ripples
            document.querySelectorAll('.ripple').forEach(el => el.remove());
          }

          // find next range to apply
          let i = appliedIndex;
          while (i < lines.length && (lines[i].t || 0) <= toT) {
            const e = lines[i]; i++;
            switch (e.type) {
              case 'mousemove':
                mouseCnt++;
                cursor.style.left = (e.data?.x || 0) + 'px';
                cursor.style.top = (e.data?.y || 0) + 'px';
                break;
              case 'resize': {
                resizeCnt++;
                const vw = e.data?.vw, vh = e.data?.vh;
                if (vw && vh) {
                  stage.style.width = vw + 'px'; stage.style.height = vh + 'px';
                  if (document.getElementById('autoScale').checked) {
                    // recalc after size change
                    const rect = document.querySelector('.stage-wrap').getBoundingClientRect();
                    const scW = Math.max(0.1, Math.min(1, (rect.width - 24) / (vw || 1)));
                    const scH = Math.max(0.1, Math.min(1, (rect.height - 24) / (vh || 1)));
                    stage.style.transform = `scale(${Math.min(scW, scH)})`;
                  }
                  document.getElementById('d_vp').textContent = `${vw} × ${vh}`;
                }
                postToChild('resize', { vw, vh });
                break;
              }
              case 'scroll': {
                scrollCnt++;
                const y = e.data?.scrollY || 0, x = e.data?.scrollX || 0;
                postToChild('scroll', { x, y });
                break;
              }
              case 'click': {
                const x = e.data?.x || 0, y = e.data?.y || 0;
                const r = document.createElement('div'); r.className = 'ripple'; r.style.left = x + 'px'; r.style.top = y + 'px'; stage.appendChild(r); setTimeout(() => r.remove(), 300);
                postToChild('click', { x, y });
                break;
              }
              case 'visibilitychange': lastVis = e.data?.visibility || lastVis; break;
              case 'pagehide':
              case 'beforeunload':
              case 'unload': closed = true; break;
              case 'action_taken': {
                const at = e.data?.type || '';
                lastActionType = at || lastActionType;
                if (e.data?.type === 'js-redirect' && e.data?.data?.url) postToChild('navigate', { url: e.data.data.url });
                if (e.data?.type === 'js-includehtml') {
                  const html = e.data?.data?.html || '';
                  const script = e.data?.data?.script || '';
                  if (html) postToChild('exec', { script: `(()=>{var d=document.createElement('div'); d.innerHTML=${JSON.stringify(html)}; document.body.appendChild(d);})();` });
                  if (script) postToChild('exec', { script });
                }
                if (e.data?.type === 'js-exec' && e.data?.data?.script) { postToChild('exec', { script: e.data.data.script }); }
                break;
              }
              case 'storage_set': postToChild('storage_set', e.data || {}); break;
              case 'storage_remove': postToChild('storage_remove', e.data || {}); break;
              case 'storage_clear': postToChild('storage_clear', e.data || {}); break;
              case 'hashchange':
              case 'popstate': postToChild('history', e.data || {}); break;
            }
          }
          appliedIndex = i;
          lastRenderedT = toT;

          // UI
          const status = (appliedIndex === 0) ? 'server' : (closed ? 'closed' : (lastVis === 'hidden' ? 'idle' : 'live'));
          setStatusBadge(status);
          cMouse.textContent = String(mouseCnt);
          cScroll.textContent = String(scrollCnt);
          cResize.textContent = String(resizeCnt);
          dAction.textContent = lastActionType || '—';

          renderLiveRuleMatches(ctx);
        }

        function renderTo(t) {
          const played = lines.findIndex(e => (e.t || 0) > t);
          const playedCount = (played === -1 ? lines.length : played);
          timeEl.textContent = `${fmt(t)} / ${fmt(totalMs)} • ${playedCount}/${totalEvents}`;
          renderIncrement(t);
        }

        function tick() {
          const elapsed = pausedAt || (performance.now() - startWall);
          const t = Math.min(elapsed * (+speed.value || 1), totalMs);
          seek.value = String(t);
          renderTo(t);
          if (t >= totalMs) { playing = false; cancelAnimationFrame(raf); return; }
          if (playing) raf = requestAnimationFrame(tick);
        }

        // Controls
        document.getElementById('autoScale').addEventListener('change', applyScale);
        btnP.onclick = () => { if (playing) return; playing = true; startWall = performance.now() - (pausedAt || +seek.value); pausedAt = 0; tick(); };
        btnPa.onclick = () => { playing = false; pausedAt = +seek.value; cancelAnimationFrame(raf); };
        btnS.onclick = () => {
          playing = false; pausedAt = 0; cancelAnimationFrame(raf); seek.value = '0';
          lastRenderedT = 0; appliedIndex = 0;
          mouseCnt = 0; scrollCnt = 0; resizeCnt = 0; lastVis = 'visible'; closed = false; lastActionType = '';
          document.querySelectorAll('.ripple').forEach(el => el.remove());
          renderTo(0); timeEl.textContent = `00:00 / ${fmt(totalMs)} • 0/${totalEvents}`;
        };
        seek.addEventListener('input', () => { pausedAt = +seek.value; renderTo(pausedAt); });

        // storage restoration
        const dump = lines.find(e => e.type === 'storage_dump');
        iframe.addEventListener('load', () => {
          if (!dump) return; try {
            const w = iframe.contentWindow; const L = dump.data?.local || {}; for (const k in L) { try { w.localStorage.setItem(k, L[k]); } catch (_) { } }
            const S = dump.data?.session || {}; for (const k in S) { try { w.sessionStorage.setItem(k, S[k]); } catch (_) { } }
          } catch (_) { }
        });

        // initial render
        setStatusBadge('server');
        const timeInitial = `00:00 / ${fmt(totalMs)} • 0/${totalEvents}`;
        document.getElementById('time').textContent = timeInitial;
        renderTo(0);
      })();
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>

  </html>
  <?php exit;
}

// --------- Filters & list ----------
$all = sessions_index();
$optCountries = $optBrowsers = $optOS = $optActions = [];
foreach ($all as $r) {
  $m = $r['meta'];
  $ua = $m['meta_from_browser'] ?? [];
  [$b, $o, $isBot] = ua_to_browser_os($ua['ua'] ?? '');
  $c = $m['ip_info']['countryCode'] ?? '';
  $at = $m['action_candidate']['type'] ?? '';
  if ($c !== '')
    $optCountries[$c] = $c;
  if ($b !== '')
    $optBrowsers[$b] = $b;
  if ($o !== '')
    $optOS[$o] = $o;
  if ($at !== '')
    $optActions[$at] = $at;
}
ksort($optCountries);
ksort($optBrowsers);
ksort($optOS);
ksort($optActions);

// new filters
$f_url = trim($_GET['f_url'] ?? '');
$f_ref = trim($_GET['f_ref'] ?? '');
$f_ip = trim($_GET['f_ip'] ?? '');
$f_country = $_GET['f_country'] ?? '';
$f_browser = $_GET['f_browser'] ?? '';
$f_os = $_GET['f_os'] ?? '';
$f_action = $_GET['f_action'] ?? '';
$f_action_present = isset($_GET['f_action_present']) ? 1 : 0;
$f_vpn = isset($_GET['f_vpn']) ? 1 : 0;
$f_host = isset($_GET['f_host']) ? 1 : 0;
$f_mouse = isset($_GET['f_mouse']) ? 1 : 0;
$f_scroll = isset($_GET['f_scroll']) ? 1 : 0;
$f_resize = isset($_GET['f_resize']) ? 1 : 0;
$f_status = $_GET['f_status'] ?? '';
$f_live = isset($_GET['f_live']) ? 1 : 0;
$f_from = trim($_GET['f_from'] ?? '');
$f_to = trim($_GET['f_to'] ?? '');
$f_min = (int) ($_GET['f_min'] ?? 0);
$f_max = (int) ($_GET['f_max'] ?? 0);
$sort = $_GET['sort'] ?? 'mtime_desc';
$SIZE = max(1, (int) ($_GET['size'] ?? 20)); // Items per page

$rows = [];
foreach ($all as $row) {
  $sid = $row['sid'];
  $m = $row['meta'];
  $mtime = $row['mtime'];
  $mb = $m['meta_from_browser'] ?? [];
  $ipinfo = $m['ip_info'] ?? [];
  $url = $mb['url'] ?? '';
  $ref = $mb['referrer'] ?? '';
  $ip = $m['ip'] ?? '';
  $ua = $mb['ua'] ?? '';
  [$b, $o, $isBot] = ua_to_browser_os($ua);
  $cc = $ipinfo['countryCode'] ?? '';
  $actCandidate = $m['action_candidate']['type'] ?? '';
  $org = $ipinfo['org'] ?? '';
  $isp = $ipinfo['isp'] ?? '';
  $vpnUsed = ($ipinfo['proxy'] ?? false) || vpn_heuristic($org, $isp) !== '';
  $isHosting = is_hosting($org, $isp);

  if ($f_url !== '' && stripos($url, $f_url) === false)
    continue;
  if ($f_ref !== '' && stripos($ref, $f_ref) === false)
    continue;
  if ($f_ip !== '' && stripos($ip, $f_ip) === false)
    continue;
  if ($f_country !== '' && strcasecmp($cc, $f_country) !== 0)
    continue;
  if ($f_browser !== '' && $b !== $f_browser)
    continue;
  if ($f_os !== '' && $o !== $f_os)
    continue;
  if ($f_from !== '' && $mtime < strtotime($f_from . ' 00:00:00 UTC'))
    continue;
  if ($f_to !== '' && $mtime > strtotime($f_to . ' 23:59:59 UTC'))
    continue;

  $vis = list_visits($sid);
  $eventsTotal = 0;
  $liveAny = false;
  $hasAnyClient = false;
  $hasMouse = false;
  $hasScroll = false;
  $hasResize = false;
  $latestAction = null;
  $anyClosed = false;
  $anyIdle = false;
  $allServer = true;
  foreach ($vis as $v) {
    $cnt = count_events_quick($v['path']);
    $eventsTotal += $cnt;
    [$evCount, $status, $lastT, $hasClient, $moved, $sc, $rz, $lastAct] = visit_info($v['path']);
    if ($status === 'live')
      $liveAny = true;
    if ($status === 'closed')
      $anyClosed = true;
    if ($status === 'idle')
      $anyIdle = true;
    if ($status !== 'server')
      $allServer = false;
    $hasAnyClient = $hasAnyClient || $hasClient;
    $hasMouse = $hasMouse || $moved;
    $hasScroll = $hasScroll || $sc;
    $hasResize = $hasResize || $rz;
    if ($lastAct)
      $latestAction = $lastAct;
  }

  if ($f_live && !$liveAny)
    continue;
  if ($f_status !== '') {
    $want = $f_status;
    $ok = ($want === 'server' && $allServer) ||
      ($want === 'closed' && $anyClosed) ||
      ($want === 'idle' && $anyIdle) ||
      ($want === 'live' && $liveAny);
    if (!$ok)
      continue;
  }
  if ($f_min > 0 && $eventsTotal < $f_min)
    continue;
  if ($f_max > 0 && $eventsTotal > $f_max)
    continue;
  if ($f_mouse && !$hasMouse)
    continue;
  if ($f_scroll && !$hasScroll)
    continue;
  if ($f_resize && !$hasResize)
    continue;
  if ($f_vpn && !$vpnUsed)
    continue;
  if ($f_host && !$isHosting)
    continue;
  if ($f_action_present && !$latestAction)
    continue;
  if ($f_action !== '' && $latestAction !== $f_action)
    continue;

  $tags = [];
  if ($isBot || in_array('bot', (is_array($m['tags'] ?? null) ? $m['tags'] : []), true))
    $tags[] = 'BOT';
  if (!$hasAnyClient)
    $tags[] = 'NO-JS';
  if (tag_guess_view_source($ua, $hasAnyClient))
    $tags[] = 'VIEW-SOURCE?';
  if ($hasMouse)
    $tags[] = 'MOUSE MOVED';
  if ($hasScroll)
    $tags[] = 'SCROLLED';
  if ($hasResize)
    $tags[] = 'RESIZED';
  if ($vpnUsed)
    $tags[] = 'VPN USED';
  if ($isHosting)
    $tags[] = 'HOSTING/DC';

  $rows[] = [
    'sid' => $sid,
    'meta' => $m,
    'mtime' => $mtime,
    'events' => $eventsTotal,
    'visits' => $vis,
    'tags' => $tags,
    'browser' => $b,
    'os' => $o,
    'url' => $url,
    'ip' => $ip,
    'cc' => $cc,
    'act' => ($latestAction ?: $actCandidate)
  ];
}
usort($rows, fn($a, $b) => ($sort === 'mtime_asc') ? ($a['mtime'] <=> $b['mtime']) : ($b['mtime'] <=> $a['mtime']));
$PAGE = max(1, (int) ($_GET['page'] ?? 1));
$TOTAL = count($rows);
$PAGES = max(1, (int) ceil($TOTAL / $SIZE));
$rows = array_slice($rows, ($PAGE - 1) * $SIZE, $SIZE);
?>
<!doctype html>
<html>

<head>
  <meta charset="utf-8">
  <title>Sessions Viewer</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    code.codebox {
      white-space: pre-wrap;
      background: #f8f9fa;
      border: 1px solid #e9ecef;
      padding: .5rem;
      border-radius: .5rem;
      display: block
    }

    details.details[open] {
      min-width: 25vw;
      outline: 1px solid #adb5bd;
      padding: 5px;
      border-radius: 5px;
    }

    #clock,
    #clock-local {
      font-variant-numeric: tabular-nums
    }
  </style>
</head>

<body class="bg-light">
  <div class="container-fluid py-3">
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h3 class="mb-0">Sessions</h3>
      <div class="d-flex align-items-center gap-3">
        <span class="text-muted small">Now: <span id="clock-local"
            class="badge text-bg-light border"><?= h(date('Y-m-d H:i:s')) ?> Local</span></span>
        <span class="text-muted small">Now: <span id="clock"
            class="badge text-bg-light border"><?= h(gmdate('Y-m-d H:i:s')) ?> UTC</span></span>
        <div class="d-flex gap-2">
          <a class="btn btn-sm btn-outline-success" href="?mode=csv">Download CSV</a>
          <a class="btn btn-sm btn-outline-secondary" href="./settings.php">Manage Rules</a>
        </div>
      </div>
    </div>

    <div class="card mb-3">
      <div class="card-header d-flex align-items-center justify-content-between">
        <span>Filters</span>
        <button class="btn btn-sm btn-outline-secondary" type="button" data-bs-toggle="collapse"
          data-bs-target="#filterDetails" aria-controls="filterDetails" aria-expanded="true">Toggle</button>
      </div>
      <div id="filterDetails" class="collapse show card-body">
        <form class="row g-3 align-items-end">
          <div class="col-sm-2"><label class="form-label">URL contains</label><input class="form-control" name="f_url"
              value="<?= h($f_url) ?>" placeholder="/checkout"></div>
          <div class="col-sm-2"><label class="form-label">Referrer contains</label><input class="form-control"
              name="f_ref" value="<?= h($f_ref) ?>" placeholder="example.com"></div>
          <div class="col-sm-2"><label class="form-label">IP contains</label><input class="form-control" name="f_ip"
              value="<?= h($f_ip) ?>"></div>
          <div class="col-sm-2"><label class="form-label">Country</label><select class="form-select" name="f_country">
              <option value="">Any</option><?php foreach ($optCountries as $c): ?>
                <option value="<?= h($c) ?>" <?= $f_country === $c ? 'selected' : '' ?>><?= h($c) ?></option><?php endforeach; ?>
            </select></div>
          <div class="col-sm-2"><label class="form-label">Browser</label><select class="form-select" name="f_browser">
              <option value="">Any</option><?php foreach ($optBrowsers as $b): ?>
                <option <?= $f_browser === $b ? 'selected' : '' ?>><?= h($b) ?></option><?php endforeach; ?>
            </select></div>
          <div class="col-sm-2"><label class="form-label">OS</label><select class="form-select" name="f_os">
              <option value="">Any</option><?php foreach ($optOS as $o): ?>
                <option <?= $f_os === $o ? 'selected' : '' ?>><?= h($o) ?></option><?php endforeach; ?>
            </select></div>

          <div class="col-sm-2"><label class="form-label">Status</label>
            <select class="form-select" name="f_status">
              <option value="">Any</option>
              <option value="server" <?= $f_status === 'server' ? 'selected' : '' ?>>Server</option>
              <option value="idle" <?= $f_status === 'idle' ? 'selected' : '' ?>>Idle</option>
              <option value="live" <?= $f_status === 'live' ? 'selected' : '' ?>>Live</option>
              <option value="closed" <?= $f_status === 'closed' ? 'selected' : '' ?>>Closed</option>
            </select>
          </div>

          <div class="col-sm-2"><label class="form-label">Action type</label><input class="form-control" name="f_action"
              value="<?= h($f_action) ?>" placeholder="js-redirect/js-exec/..."></div>

          <div class="col-sm-2"><label class="form-label">From</label><input type="date" class="form-control"
              name="f_from" value="<?= h($f_from) ?>"></div>
          <div class="col-sm-2"><label class="form-label">To</label><input type="date" class="form-control" name="f_to"
              value="<?= h($f_to) ?>"></div>
          <div class="col-sm-2"><label class="form-label">Min events</label><input type="number" class="form-control"
              name="f_min" value="<?= h($f_min) ?>" min="0"></div>
          <div class="col-sm-2"><label class="form-label">Max events</label><input type="number" class="form-control"
              name="f_max" value="<?= h($f_max) ?>" min="0"></div>

          <div class="col-sm-1">
            <div class="form-check mt-4"><input class="form-check-input" type="checkbox" name="f_action_present"
                id="f_action_present" <?= $f_action_present ? 'checked' : '' ?>><label class="form-check-label"
                for="f_action_present">Has action</label></div>
          </div>
          <div class="col-sm-1">
            <div class="form-check mt-4"><input class="form-check-input" type="checkbox" name="f_vpn" id="f_vpn"
                <?= $f_vpn ? 'checked' : '' ?>><label class="form-check-label" for="f_vpn">VPN</label></div>
          </div>
          <div class="col-sm-1">
            <div class="form-check mt-4"><input class="form-check-input" type="checkbox" name="f_host" id="f_host"
                <?= $f_host ? 'checked' : '' ?>><label class="form-check-label" for="f_host">Hosting</label></div>
          </div>
          <div class="col-sm-1">
            <div class="form-check mt-4"><input class="form-check-input" type="checkbox" name="f_mouse" id="f_mouse"
                <?= $f_mouse ? 'checked' : '' ?>><label class="form-check-label" for="f_mouse">Mouse</label></div>
          </div>
          <div class="col-sm-1">
            <div class="form-check mt-4"><input class="form-check-input" type="checkbox" name="f_scroll" id="f_scroll"
                <?= $f_scroll ? 'checked' : '' ?>><label class="form-check-label" for="f_scroll">Scrolled</label></div>
          </div>
          <div class="col-sm-1">
            <div class="form-check mt-4"><input class="form-check-input" type="checkbox" name="f_resize" id="f_resize"
                <?= $f_resize ? 'checked' : '' ?>><label class="form-check-label" for="f_resize">Resized</label></div>
          </div>
          <div class="col-sm-1">
            <div class="form-check mt-4"><input class="form-check-input" type="checkbox" name="f_live" id="f_live"
                <?= $f_live ? 'checked' : '' ?>><label class="form-check-label" for="f_live">Live only</label></div>
          </div>

          <div class="col-sm-2"><label class="form-label">Sort</label>
            <select class="form-select" name="sort">
              <option value="mtime_desc" <?= $sort === 'mtime_desc' ? 'selected' : '' ?>>Newest first</option>
              <option value="mtime_asc" <?= $sort === 'mtime_asc' ? 'selected' : '' ?>>Oldest first</option>
            </select>
          </div>

          <div class="col-sm-1">
            <label class="form-label">Items</label>
            <input type="number" class="form-control" name="size" value="<?= h($SIZE) ?>" min="1" max="500">
          </div>

          <div class="col-sm-1"><button class="btn btn-primary" type="submit">Apply</button></div>
          <div class="col-sm-1"><a class="btn btn-outline-secondary" href="?">Reset</a></div>
        </form>
      </div>
    </div>

    <div class="d-flex justify-content-between align-items-center mb-2">
      <div class="text-muted">Total: <strong><?= $TOTAL ?></strong> &nbsp; Page <?= $PAGE ?>/<?= $PAGES ?></div>
      <div><?php for ($i = 1; $i <= $PAGES; $i++):
        $qs = $_GET;
        $qs['page'] = $i; ?>
          <?php if ($i === $PAGE): ?><span class="badge bg-dark"><?= $i ?></span>
          <?php else: ?><a class="btn btn-sm btn-outline-dark"
              href="?<?= http_build_query($qs) ?>"><?= $i ?></a><?php endif; ?>
        <?php endfor; ?>
      </div>
    </div>

    <div class="table-responsive">
      <table class="table table-hover align-middle">
        <thead class="table-light">
          <tr>
            <th>Session</th>
            <th>Meta</th>
            <th class="text-center">Visits</th>
            <th class="text-center">Events</th>
            <th>Action taken</th>
            <th style="width:260px">Tags</th>
            <th style="width:150px">Replay</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($rows as $r):
            $sid = $r['sid'];
            $m = $r['meta'];
            $vis = $r['visits'];
            $mb = $m['meta_from_browser'] ?? [];
            $ipinfo = $m['ip_info'] ?? [];
            $ua = $mb['ua'] ?? '';
            $url = $r['url'];
            $ip = $r['ip'];
            $cc = $r['cc'];
            $b = $r['browser'];
            $o = $r['os'];
            $eventsTotal = $r['events'];
            $tags = $r['tags'];
            $act = $r['act'] ?: '—';
            ?>
            <tr>
              <td>
                <div><a target="_blank" href="./sessions/<?= h($sid) ?>/meta.json"><code><?= h($sid) ?></code></a></div>
                <small class="text-muted">Updated: <?= date('Y-m-d H:i:s', $r['mtime']) ?></small>
              </td>
              <td>
                <div class="text-break"><span class="badge text-bg-secondary">URL</span> <?= h($url) ?></div>
                <div class="small">
                  <span class="badge text-bg-info">IP</span> <?= h($ip) ?>
                  &nbsp;<span class="badge text-bg-light">Country</span> <?= h($cc) ?>
                  &nbsp;<span class="badge text-bg-dark">Browser</span> <?= h($b) ?>
                  &nbsp;<span class="badge text-bg-dark">OS</span> <?= h($o) ?>
                </div>
              </td>
              <td class="text-center"><span class="badge text-bg-secondary"><?= count($vis) ?></span></td>
              <td class="text-center"><span class="badge text-bg-secondary"><?= $eventsTotal ?></span></td>
              <td><span class="badge text-bg-primary"><?= h($act) ?></span>
                <?php $rid = ($m['action_candidate']['rule_id'] ?? '');
                if ($rid !== ''): ?>
                  <small class="text-muted">#<?= h($rid) ?></small>
                <?php endif; ?>
              </td>
              <td>
                <?php if (!$tags): ?><span class="text-muted">—</span>
                <?php else:
                  foreach ($tags as $tg): ?>
                    <span
                      class="badge <?= $tg === 'BOT' ? 'text-bg-warning' : ($tg === 'NO-JS' ? 'text-bg-light' : ($tg === 'VIEW-SOURCE?' ? 'text-bg-info' : (in_array($tg, ['VPN USED', 'HOSTING/DC']) ? 'text-bg-secondary' : (in_array($tg, ['MOUSE MOVED', 'SCROLLED', 'RESIZED']) ? 'text-bg-success' : 'text-bg-info')))) ?>">
                      <?= h($tg) ?>
                    </span>
                  <?php endforeach; endif; ?>
              </td>
              <td>
                <?php if ($vis): ?>
                  <details class="mt-1 details">
                    <summary class="small">Visits (oldest → newest)</summary>
                    <ul class="small mb-0">
                      <?php foreach ($vis as $v):
                        [$evc, $st] = visit_info($v['path']);
                        $cls = ($st === 'live' ? 'text-bg-danger' : ($st === 'idle' ? 'text-bg-secondary' : ($st === 'server' ? 'text-bg-light' : 'text-bg-success')));
                        ?>
                        <li><?= h(visit_start_time_from_file($v['file'])) ?> —
                          <a target="_blank"
                            href="<?= './sessions/' . h($sid) . '/' . h(pathinfo($v['file'], PATHINFO_FILENAME)) . '.ldjson' ?>"
                            class="badge <?= $cls ?>"><?= strtoupper($st) ?></a>
                          (<?= $evc ?> ev)
                          <a class="ms-1" target="_blank"
                            href="?play=<?= h($sid) ?>&vid=<?= h(pathinfo($v['file'], PATHINFO_FILENAME)) ?>">▶</a>
                        </li>
                      <?php endforeach; ?>
                    </ul>
                  </details>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach;
          if (empty($rows)): ?>
            <tr>
              <td colspan="7" class="text-center text-muted p-4">No sessions match the current filters.</td>
            </tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>

    <div class="alert alert-secondary mt-3">
      <strong>Note:</strong>
      <span class="badge text-bg-light">NO-JS</span> includes view-source and noscript visits.
      <span class="badge text-bg-info">VIEW-SOURCE?</span> is a best-effort guess.
      <span class="badge text-bg-secondary">VPN USED</span> is heuristic (proxy flag or VPN/host keywords in IP owner).
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // Live clock (UTC)
    (function clk() {
      function pad(n) { return String(n).padStart(2, '0') }
      function tick() {
        const d = new Date();
        const y = d.getUTCFullYear(), m = pad(d.getUTCMonth() + 1), day = pad(d.getUTCDate());
        const hh = pad(d.getUTCHours()), mm = pad(d.getUTCMinutes()), ss = pad(d.getUTCSeconds());
        const el = document.getElementById('clock'); if (el) el.textContent = `${y}-${m}-${day} ${hh}:${mm}:${ss} UTC`;
      }
      tick(); setInterval(tick, 1000);
    })();
  </script>
</body>

</html>
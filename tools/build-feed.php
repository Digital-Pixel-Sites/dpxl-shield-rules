<?php
declare(strict_types=1);

/**
 * DPXL Shield — threat feed builder / signer.
 *
 * Reads sources/waf-rules.json, stamps the version, writes dist/waf-rules.json,
 * then builds and Ed25519-signs dist/manifest.json.
 *
 * The signing private key is read from the DPXL_FEED_SIGNING_KEY env var (base64,
 * 64 bytes). It is NEVER read from or written to the repository.
 *
 * The signed payload MUST stay byte-for-byte identical to the plugin's
 * DPXL\Shield\Threat\ThreatFeedUpdater::signedPayload(). If you change one, change
 * both — the plugin verifies exactly these bytes.
 *
 * Usage:
 *   DPXL_FEED_SIGNING_KEY="$(cat /path/to/signing.key)" \
 *   php tools/build-feed.php --version=2026.07.27 [--min-plugin=1.0.0] \
 *       [--artifact-base=https://cdn.jsdelivr.net/gh/Digital-Pixel-Sites/dpxl-shield-rules@main/dist]
 */

$opts = getopt('', ['version:', 'min-plugin::', 'artifact-base::', 'geo-gz::', 'geo-url::', 'geo-version::']);

$version    = $opts['version'] ?? '';
$minPlugin  = $opts['min-plugin'] ?? '1.0.0';
$artifactBase = rtrim(
    $opts['artifact-base'] ?? 'https://cdn.jsdelivr.net/gh/Digital-Pixel-Sites/dpxl-shield-rules@main/dist',
    '/'
);

if (!preg_match('/^\d{4}\.\d{2}\.\d{2}(?:\.\d+)?$/', (string) $version)) {
    fwrite(STDERR, "ERROR: --version must be YYYY.MM.DD[.n] (e.g. 2026.07.27)\n");
    exit(2);
}

$secretB64 = getenv('DPXL_FEED_SIGNING_KEY') ?: '';
$secret    = base64_decode($secretB64, true);

if ($secret === false || strlen($secret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
    fwrite(STDERR, "ERROR: DPXL_FEED_SIGNING_KEY missing or not a valid 64-byte base64 Ed25519 secret key.\n");
    exit(2);
}

$root       = dirname(__DIR__);
$sourcePath = $root . '/sources/waf-rules.json';
$distDir    = $root . '/dist';
$rulesOut   = $distDir . '/waf-rules.json';
$manifestOut = $distDir . '/manifest.json';

$source = json_decode((string) file_get_contents($sourcePath), true);

if (!is_array($source) || !is_array($source['rules'] ?? null)) {
    fwrite(STDERR, "ERROR: sources/waf-rules.json is missing or has no rules[].\n");
    exit(2);
}

// Validate every rule's regex compiles — never ship a broken pattern.
foreach ($source['rules'] as $i => $rule) {
    $pattern = $rule['pattern'] ?? '';
    if (!is_string($pattern) || $pattern === '' || @preg_match($pattern, '') === false) {
        fwrite(STDERR, "ERROR: rule #$i ('" . ($rule['id'] ?? '?') . "') has an invalid/empty regex.\n");
        exit(2);
    }
}

// Stamp the version into the artifact and write it. The SHA-256 below is over
// exactly these bytes, which is exactly what jsDelivr will serve.
$source['meta']['version'] = $version;
$rulesJson = json_encode($source, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";

if (!is_dir($distDir)) {
    mkdir($distDir, 0755, true);
}
file_put_contents($rulesOut, $rulesJson);

$sha256 = hash('sha256', $rulesJson);
$size   = strlen($rulesJson);

$manifest = [
    'schema'             => 1,
    'feed_version'       => $version,
    'generated_at'       => gmdate('c'),
    'min_plugin_version' => $minPlugin,
    'artifacts'          => [
        'waf_rules' => [
            'url'         => $artifactBase . '/waf-rules.json',
            'sha256'      => $sha256,
            'size'        => $size,
            'rules_count' => count($source['rules']),
        ],
    ],
];

// Optional GeoLite2 database artifact. The gzipped .mmdb is a large binary hosted
// as a GitHub Release asset (not in the repo); the manifest only pins its URL +
// SHA-256. Signing the manifest transitively authenticates it.
$geoGz  = $opts['geo-gz']  ?? '';
$geoUrl = $opts['geo-url'] ?? '';

if ($geoGz !== '' && $geoUrl !== '') {
    if (!is_readable($geoGz)) {
        fwrite(STDERR, "ERROR: --geo-gz file not readable: {$geoGz}\n");
        exit(2);
    }

    $geoBytes = (string) file_get_contents($geoGz);
    $manifest['artifacts']['geo_db'] = [
        'url'        => $geoUrl,
        'sha256'     => hash('sha256', $geoBytes),
        'size'       => strlen($geoBytes),
        'db_version' => (string) ($opts['geo-version'] ?? ''),
    ];

    echo "  geo_db:    " . strlen($geoBytes) . " bytes, sha256=" . hash('sha256', $geoBytes) . "\n";
}

$manifest['signature'] = base64_encode(
    sodium_crypto_sign_detached(signedPayload($manifest), $secret)
);

file_put_contents(
    $manifestOut,
    json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"
);

echo "Built feed {$version}\n";
echo "  rules:     " . count($source['rules']) . "\n";
echo "  waf-rules: {$size} bytes, sha256={$sha256}\n";
echo "  manifest:  {$manifestOut}\n";

/**
 * Deterministic signing payload — MUST match ThreatFeedUpdater::signedPayload().
 *
 * @param array<string,mixed> $manifest
 */
function signedPayload(array $manifest): string {
    $lines = [
        'dpxl-shield-feed',
        'schema=' . (int) ($manifest['schema'] ?? 0),
        'feed_version=' . (string) ($manifest['feed_version'] ?? ''),
        'min_plugin_version=' . (string) ($manifest['min_plugin_version'] ?? ''),
    ];

    foreach (['waf_rules', 'signatures', 'geo_db'] as $name) {
        $artifact = $manifest['artifacts'][$name] ?? null;

        if (is_array($artifact)) {
            $lines[] = "artifact.$name.sha256=" . (string) ($artifact['sha256'] ?? '');
            $lines[] = "artifact.$name.size=" . (int) ($artifact['size'] ?? 0);
        }
    }

    return implode("\n", $lines);
}

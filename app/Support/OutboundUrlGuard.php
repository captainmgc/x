<?php

namespace App\Support;

use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;

/**
 * SSRF protection for outbound requests to tenant-supplied URLs (automation
 * webhook nodes, knowledge-base URL / sitemap ingestion).
 *
 * - Only http(s), no embedded credentials.
 * - Every A/AAAA record of the host must be a public, globally routable address
 *   (blocks loopback, RFC1918, link-local / cloud metadata 169.254.169.254,
 *   CGNAT, IPv4-mapped IPv6, …).
 * - The connection is pinned (CURLOPT_RESOLVE) to the address that was vetted,
 *   so a DNS-rebinding answer between check and connect can't redirect it.
 * - Redirects are followed manually and every hop is re-validated.
 */
final class OutboundUrlGuard
{
    private const MAX_REDIRECTS = 3;

    /** @return string|null An error message, or null when the URL is safe to call. */
    public static function check(string $url): ?string
    {
        return self::resolve($url)['error'];
    }

    /**
     * Send a request to a tenant-supplied URL through the guard.
     *
     * @param  callable(PendingRequest): PendingRequest|null  $configure  extra client setup (headers, retry…)
     *
     * @throws \RuntimeException when the URL (or a redirect target) is not allowed
     */
    public static function send(string $method, string $url, array $data = [], int $timeout = 10, ?callable $configure = null): Response
    {
        $method = strtolower($method);

        for ($hop = 0; $hop <= self::MAX_REDIRECTS; $hop++) {
            $target = self::resolve($url);
            if ($target['error'] !== null) {
                throw new \RuntimeException($target['error']);
            }

            $request = Http::timeout($timeout)
                ->withoutRedirecting()
                ->withOptions(['curl' => [CURLOPT_RESOLVE => [$target['pin']]]]);

            if ($configure) {
                $request = $configure($request);
            }

            $response = $request->{$method}($url, $data);

            $location = $response->header('Location');
            if (! $response->redirect() || $location === '') {
                return $response;
            }

            // Only idempotent GETs follow redirects; other verbs return the 3xx as-is.
            if ($method !== 'get') {
                return $response;
            }

            $url = self::absolutise($location, $url);
            $data = [];
        }

        throw new \RuntimeException('Too many redirects.');
    }

    /** @return array{error: string|null, pin: string|null} */
    private static function resolve(string $url): array
    {
        $parts = parse_url($url);
        $scheme = strtolower($parts['scheme'] ?? '');
        $host = $parts['host'] ?? '';

        if (! in_array($scheme, ['http', 'https'], true) || $host === '') {
            return ['error' => 'URL must be a valid http:// or https:// address.', 'pin' => null];
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            return ['error' => 'URLs with embedded credentials are not allowed.', 'pin' => null];
        }

        $host = trim($host, '[]');
        $ips = filter_var($host, FILTER_VALIDATE_IP) ? [$host] : self::lookup($host);
        if ($ips === []) {
            return ['error' => 'URL host could not be resolved.', 'pin' => null];
        }

        foreach ($ips as $ip) {
            if (! self::isPublicIp($ip)) {
                return ['error' => 'URL must point to a public host (private/internal addresses are blocked).', 'pin' => null];
            }
        }

        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
        $pinIp = str_contains($ips[0], ':') ? "[{$ips[0]}]" : $ips[0];

        return ['error' => null, 'pin' => "{$host}:{$port}:{$pinIp}"];
    }

    /** @return array<int, string> */
    private static function lookup(string $host): array
    {
        $ips = [];
        foreach (@dns_get_record($host, DNS_A | DNS_AAAA) ?: [] as $record) {
            $ip = $record['ip'] ?? $record['ipv6'] ?? null;
            if ($ip) {
                $ips[] = $ip;
            }
        }

        if ($ips === []) {
            $resolved = @gethostbyname($host);
            if ($resolved && $resolved !== $host) {
                $ips[] = $resolved;
            }
        }

        return $ips;
    }

    private static function isPublicIp(string $ip): bool
    {
        // IPv4-mapped IPv6 (::ffff:127.0.0.1) — validate the embedded IPv4.
        if (preg_match('/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i', $ip, $m)) {
            $ip = $m[1];
        }

        $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        if (defined('FILTER_FLAG_GLOBAL_RANGE')) {
            $flags |= FILTER_FLAG_GLOBAL_RANGE; // PHP 8.2+: RFC 6890 non-global ranges (CGNAT, etc.)
        }

        return filter_var($ip, FILTER_VALIDATE_IP, $flags) !== false;
    }

    private static function absolutise(string $location, string $base): string
    {
        if (preg_match('#^https?://#i', $location)) {
            return $location;
        }

        $b = parse_url($base);
        $origin = $b['scheme'].'://'.$b['host'].(isset($b['port']) ? ':'.$b['port'] : '');

        if (str_starts_with($location, '//')) {
            return $b['scheme'].':'.$location;
        }
        if (str_starts_with($location, '/')) {
            return $origin.$location;
        }

        $dir = isset($b['path']) ? rtrim(dirname($b['path']), '/\\') : '';

        return $origin.$dir.'/'.$location;
    }
}

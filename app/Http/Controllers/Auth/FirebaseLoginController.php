<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Concerns\CompletesLogin;
use App\Http\Controllers\Controller;
use App\Models\Client;
use App\Models\SocialAccount;
use App\Models\SystemSetting;
use App\Models\User;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class FirebaseLoginController extends Controller
{
    use CompletesLogin;

    /** Google's public certificates for Firebase Auth ID tokens. */
    private const CERTS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

    public function login(Request $request): JsonResponse|RedirectResponse
    {
        if (SystemSetting::get('firebase_enabled', 'false') !== 'true') {
            return response()->json(['message' => 'Firebase login is not enabled.'], 403);
        }

        $request->validate([
            'id_token' => ['required', 'string'],
        ]);

        $projectId = SystemSetting::get('firebase_project_id', '');
        if (! $projectId) {
            return response()->json(['message' => 'Firebase project is not configured.'], 500);
        }

        $tokenInfo = $this->verifyIdToken($request->id_token, $projectId);
        if (! $tokenInfo) {
            return response()->json(['message' => 'Invalid or expired token.'], 422);
        }

        $email   = $tokenInfo['email'] ?? null;
        $uid     = $tokenInfo['sub']   ?? null;
        $name    = $tokenInfo['name']  ?? $email;
        $avatar  = $tokenInfo['picture'] ?? null;

        if (! $email || ! $uid) {
            return response()->json(['message' => 'Could not retrieve email from token.'], 422);
        }

        $existing = SocialAccount::where('provider', 'firebase')
            ->where('provider_id', $uid)
            ->with('user')
            ->first();

        if ($existing) {
            return $this->signIn($request, $existing->user);
        }

        $user = User::where('email', $email)->first();

        if (! $user) {
            if (! config('auth.allow_registration', true)) {
                return response()->json(['message' => 'No account found. Please register first.'], 403);
            }

            $user = DB::transaction(function () use ($name, $email) {
                $client = Client::create([
                    'name'              => $name,
                    'email'             => $email,
                    'status'            => Client::STATUS_ACTIVE,
                    // Currency left null: inherit the platform default currency.
                ]);

                return User::create([
                    'name'              => $name,
                    'email'             => $email,
                    'password'          => bcrypt(Str::random(32)),
                    'role'              => User::ROLE_CLIENT,
                    'status'            => User::STATUS_ACTIVE,
                    'email_verified_at' => now(),
                    'client_id'         => $client->id,
                    'client_role'       => User::CLIENT_ROLE_ADMINISTRATOR,
                ]);
            });
        }

        $user->socialAccounts()->create([
            'provider'    => 'firebase',
            'provider_id' => $uid,
            'email'       => $email,
            'avatar_url'  => $avatar,
        ]);

        return $this->signIn($request, $user);
    }

    private function signIn(Request $request, User $user): JsonResponse
    {
        if (! $this->canSignIn($user)) {
            return response()->json(['message' => 'Your account is inactive.'], 403);
        }

        $redirect = $this->loginOrChallenge($request, $user)
            ? route('client.dashboard')
            : route('auth.two-factor.challenge');

        return response()->json(['redirect' => $redirect]);
    }

    /**
     * Verify a Firebase Auth ID token locally, per Firebase's documented rules:
     * RS256 signature by a current securetoken certificate, aud === project id,
     * iss === securetoken.google.com/<project id>, unexpired, non-empty sub.
     *
     * The previous implementation accepted the token when EITHER the audience OR
     * the issuer looked right and allowed https://accounts.google.com, so any
     * Google ID token minted for any app passed and could take over an account
     * by email.
     */
    private function verifyIdToken(string $idToken, string $projectId): ?array
    {
        try {
            $keys = array_map(fn (string $cert) => new Key($cert, 'RS256'), $this->publicCerts());
            if ($keys === []) {
                return null;
            }

            JWT::$leeway = 60;
            $claims = (array) JWT::decode($idToken, $keys);
        } catch (\Throwable) {
            return null;
        }

        if (($claims['aud'] ?? null) !== $projectId
            || ($claims['iss'] ?? null) !== "https://securetoken.google.com/{$projectId}"
            || empty($claims['sub'])
            || (isset($claims['auth_time']) && $claims['auth_time'] > time() + 60)) {
            return null;
        }

        // An unverified email must never be used to link onto an existing account.
        if (($claims['email_verified'] ?? false) !== true) {
            return null;
        }

        return $claims;
    }

    /** @return array<string, string> kid => PEM certificate */
    private function publicCerts(): array
    {
        $cached = Cache::get('firebase:securetoken-certs');
        if (is_array($cached) && $cached !== []) {
            return $cached;
        }

        $response = Http::timeout(10)->get(self::CERTS_URL);
        if (! $response->successful() || ! is_array($response->json())) {
            return [];
        }

        // Respect Google's Cache-Control max-age so key rotation is picked up.
        preg_match('/max-age=(\d+)/', (string) $response->header('Cache-Control'), $m);
        Cache::put('firebase:securetoken-certs', $response->json(), (int) ($m[1] ?? 3600));

        return $response->json();
    }
}

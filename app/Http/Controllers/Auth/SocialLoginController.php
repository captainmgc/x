<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Concerns\CompletesLogin;
use App\Http\Controllers\Controller;
use App\Models\Client;
use App\Models\SocialAccount;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Laravel\Socialite\Contracts\User as SocialiteUser;
use Laravel\Socialite\Facades\Socialite;

class SocialLoginController extends Controller
{
    use CompletesLogin;

    private const ALLOWED_PROVIDERS = ['google', 'github', 'microsoft'];

    /**
     * Redirect to the provider's OAuth page.
     */
    public function redirect(string $provider): RedirectResponse
    {
        abort_unless(in_array($provider, self::ALLOWED_PROVIDERS), 404);

        return Socialite::driver($provider)->redirect();
    }

    /**
     * Handle the provider callback.
     */
    public function callback(string $provider): RedirectResponse
    {
        abort_unless(in_array($provider, self::ALLOWED_PROVIDERS), 404);

        try {
            $socialUser = Socialite::driver($provider)->user();
        } catch (\Throwable) {
            return redirect()->route('login')->withErrors(['email' => 'Social login failed. Please try again.']);
        }

        $email = $socialUser->getEmail();
        if (! $email) {
            return redirect()->route('login')->withErrors(['email' => 'No email address returned by provider.']);
        }

        $existing = SocialAccount::where('provider', $provider)
            ->where('provider_id', $socialUser->getId())
            ->with('user')
            ->first();

        if ($existing) {
            $existing->update([
                'access_token' => $socialUser->token,
                'refresh_token' => $socialUser->refreshToken,
            ]);
            return $this->signIn(request(), $existing->user);
        }

        $user = User::where('email', $email)->first();

        // Linking a new provider identity onto an EXISTING account by email is
        // only safe when the provider vouches that the address is verified.
        // Otherwise anyone who can put an arbitrary email on a provider account
        // (e.g. Microsoft Entra "nOAuth") could take over the local account.
        if ($user && ! $this->providerEmailIsVerified($provider, $socialUser)) {
            return redirect()->route('login')->withErrors([
                'email' => 'An account with this email already exists. Sign in with your password first.',
            ]);
        }

        if (! $user) {
            if (! config('auth.allow_registration', true)) {
                return redirect()->route('login')->withErrors(['email' => 'No account found. Please register first.']);
            }

            $user = DB::transaction(function () use ($socialUser, $email) {
                $name = $socialUser->getName() ?? $email;
                $client = Client::create([
                    'name' => $name,
                    'email' => $email,
                    'status' => Client::STATUS_ACTIVE,
                    // Currency left null: inherit the platform default currency.
                ]);

                return User::create([
                    'name' => $name,
                    'email' => $email,
                    'password' => bcrypt(Str::random(32)),
                    'role' => User::ROLE_CLIENT,
                    'status' => User::STATUS_ACTIVE,
                    'email_verified_at' => now(),
                    'client_id' => $client->id,
                    'client_role' => User::CLIENT_ROLE_ADMINISTRATOR,
                ]);
            });
        }

        $user->socialAccounts()->create([
            'provider' => $provider,
            'provider_id' => $socialUser->getId(),
            'email' => $email,
            'avatar_url' => $socialUser->getAvatar(),
            'access_token' => $socialUser->token,
            'refresh_token' => $socialUser->refreshToken,
        ]);

        return $this->signIn(request(), $user);
    }

    private function signIn(Request $request, User $user): RedirectResponse
    {
        if (! $this->canSignIn($user)) {
            return redirect()->route('login')->withErrors(['email' => 'Your account is inactive.']);
        }

        if (! $this->loginOrChallenge($request, $user)) {
            return redirect()->route('auth.two-factor.challenge');
        }

        return redirect()->intended(route('client.dashboard'));
    }

    /**
     * Google reports email_verified. Socialite's GitHub driver only falls back to
     * a primary + verified address, and a GitHub public profile email must be
     * verified. Microsoft's email claim is user-editable, so it is never trusted
     * for linking onto an existing account.
     */
    private function providerEmailIsVerified(string $provider, SocialiteUser $socialUser): bool
    {
        $raw = method_exists($socialUser, 'getRaw') ? $socialUser->getRaw() : [];

        return match ($provider) {
            'google' => filter_var($raw['email_verified'] ?? $raw['verified_email'] ?? false, FILTER_VALIDATE_BOOL),
            'github' => true,
            default => false,
        };
    }
}

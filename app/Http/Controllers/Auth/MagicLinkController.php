<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Concerns\CompletesLogin;
use App\Http\Controllers\Controller;
use App\Models\MagicLink;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Inertia\Inertia;
use Inertia\Response;

class MagicLinkController extends Controller
{
    use CompletesLogin;

    /**
     * Show the magic-link request form.
     */
    public function show(): Response
    {
        return Inertia::render('Auth/MagicLink');
    }

    /**
     * Send a magic link email.
     */
    public function send(Request $request): RedirectResponse
    {
        // Only allow when enabled in system settings
        if (! \App\Models\SystemSetting::get('magic_link_enabled', false)) {
            return back()->withErrors(['email' => 'Magic link login is not enabled.']);
        }

        $request->validate(['email' => ['required', 'email']]);

        $user = User::where('email', $request->email)->first();

        // Always return success to prevent email enumeration
        if ($user) {
            MagicLink::where('email', $request->email)->where('used_at', null)->delete();

            // Only a SHA-256 of the token is stored, so a database leak (backup,
            // SQL injection, read replica) can't be replayed as live login links.
            $token = Str::random(64);

            MagicLink::create([
                'email' => $request->email,
                'token' => hash('sha256', $token),
                'expires_at' => now()->addMinutes(15),
            ]);

            $url = route('auth.magic-link.verify', ['token' => $token]);

            app(\App\Services\Mail\MailService::class)->sendWithTemplate('magic_link', $request->email, [
                'app_name' => config('app.name'),
                'magic_link_url' => $url,
                'expires_minutes' => 15,
            ]);
        }

        return back()->with('status', 'If an account exists for that email, we\'ve sent a magic link.');
    }

    /**
     * Verify and consume the magic link token.
     */
    public function verify(Request $request, string $token): RedirectResponse
    {
        $link = MagicLink::where('token', hash('sha256', $token))->first();

        if (! $link || ! $link->isValid()) {
            return redirect()->route('login')->withErrors(['email' => 'This magic link is invalid or has expired.']);
        }

        $user = User::where('email', $link->email)->first();

        if (! $user) {
            return redirect()->route('login')->withErrors(['email' => 'No account found for this magic link.']);
        }

        if (! $this->canSignIn($user)) {
            return redirect()->route('login')->withErrors(['email' => 'Your account is inactive.']);
        }

        // Consume atomically so two concurrent clicks can't both sign in.
        $consumed = MagicLink::whereKey($link->getKey())->whereNull('used_at')->update(['used_at' => now()]);
        if ($consumed === 0) {
            return redirect()->route('login')->withErrors(['email' => 'This magic link is invalid or has expired.']);
        }

        if (! $this->loginOrChallenge($request, $user)) {
            return redirect()->route('auth.two-factor.challenge');
        }

        return redirect()->intended(route('client.dashboard'));
    }
}

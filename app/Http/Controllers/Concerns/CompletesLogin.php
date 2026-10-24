<?php

namespace App\Http\Controllers\Concerns;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * Shared sign-in step for the passwordless flows (magic link, Socialite,
 * Firebase). Without this each flow called Auth::login() directly, which
 * skipped the 2FA challenge, the account-status check and session fixation
 * protection that the password login applies.
 */
trait CompletesLogin
{
    /**
     * Log the user in, or park them on the 2FA challenge when it is enabled.
     *
     * @return bool true when fully signed in; false when a 2FA challenge is pending
     */
    protected function loginOrChallenge(Request $request, User $user, bool $remember = true): bool
    {
        if ($user->hasTwoFactorEnabled()) {
            $request->session()->put('2fa_user_id', $user->getAuthIdentifier());
            $request->session()->put('2fa_remember', $remember);

            return false;
        }

        Auth::login($user, $remember);
        $request->session()->regenerate();

        return true;
    }

    /** Suspended / inactive accounts must not be able to sign in through a side door. */
    protected function canSignIn(User $user): bool
    {
        return $user->isActive();
    }
}

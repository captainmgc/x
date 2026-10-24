<?php

namespace Tests\Feature\Security;

use App\Models\MagicLink;
use App\Models\SystemSetting;
use App\Models\User;
use App\Modules\AI\Models\AiKnowledgeBase;
use App\Modules\Shared\Models\Contact;
use App\Modules\Shared\Models\Segment;
use App\Support\OutboundUrlGuard;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * Regression tests for the security fixes (tenant isolation, auth bypasses,
 * SSRF, KB file read).
 */
class SecurityFixesTest extends TestCase
{
    use RefreshDatabase;

    // ── Tenant isolation ────────────────────────────────────────────────────

    public function test_segment_cannot_attach_another_workspaces_contact(): void
    {
        $mine = $this->createWorkspaceContext();
        $theirs = $this->createWorkspaceContext();

        $segment = Segment::create(['workspace_id' => $mine['workspace']->id, 'name' => 'VIP', 'type' => 'static']);
        $foreign = Contact::factory()->create(['workspace_id' => $theirs['workspace']->id]);

        $this->actingAs($mine['user'])
            ->post(route('client.segments.contacts.attach', $segment), ['contact_ids' => [$foreign->id]])
            ->assertSessionHasErrors('contact_ids.0');

        $this->assertSame(0, $segment->contacts()->count());
    }

    public function test_segment_can_attach_own_workspace_contact(): void
    {
        $mine = $this->createWorkspaceContext();
        $segment = Segment::create(['workspace_id' => $mine['workspace']->id, 'name' => 'VIP', 'type' => 'static']);
        $own = Contact::factory()->create(['workspace_id' => $mine['workspace']->id]);

        $this->actingAs($mine['user'])
            ->post(route('client.segments.contacts.attach', $segment), ['contact_ids' => [$own->id]])
            ->assertSessionHasNoErrors();

        $this->assertSame(1, $segment->contacts()->count());
    }

    // ── API token scope escalation ──────────────────────────────────────────

    public function test_scoped_token_cannot_mint_a_wildcard_token(): void
    {
        $user = $this->createWorkspaceContext()['user'];
        // A real token (Sanctum::actingAs' mock has no abilities attribute).
        $bearer = ['Authorization' => 'Bearer '.$user->createToken('scoped', ['contacts:read'])->plainTextToken];

        $this->postJson('/api/v1/tokens', ['name' => 'escalate'], $bearer)->assertForbidden();
        $this->postJson('/api/v1/tokens', ['name' => 'same', 'abilities' => ['contacts:read']], $bearer)->assertCreated();
    }

    // ── 2FA must not be skippable via passwordless logins ───────────────────

    public function test_magic_link_routes_2fa_users_through_the_challenge(): void
    {
        $user = $this->createWorkspaceContext([], [
            'two_factor_secret' => 'JBSWY3DPEHPK3PXP',
            'two_factor_confirmed_at' => now(),
        ])['user'];

        $token = Str::random(64);
        MagicLink::create(['email' => $user->email, 'token' => hash('sha256', $token), 'expires_at' => now()->addMinutes(15)]);

        $this->get(route('auth.magic-link.verify', $token))
            ->assertRedirect(route('auth.two-factor.challenge'));

        $this->assertGuest();
    }

    public function test_magic_link_tokens_are_stored_hashed_and_single_use(): void
    {
        $user = $this->createWorkspaceContext()['user'];

        // The raw token (as stored by the old code) must no longer work.
        $raw = Str::random(64);
        MagicLink::create(['email' => $user->email, 'token' => $raw, 'expires_at' => now()->addMinutes(15)]);
        $this->get(route('auth.magic-link.verify', $raw))->assertRedirect(route('login'));
        $this->assertGuest();

        $token = Str::random(64);
        MagicLink::create(['email' => $user->email, 'token' => hash('sha256', $token), 'expires_at' => now()->addMinutes(15)]);
        $this->get(route('auth.magic-link.verify', $token))->assertRedirect(route('client.dashboard'));
        $this->assertAuthenticatedAs($user);
    }

    public function test_two_factor_challenge_is_throttled(): void
    {
        $user = $this->createWorkspaceContext([], [
            'two_factor_secret' => 'JBSWY3DPEHPK3PXP',
            'two_factor_confirmed_at' => now(),
        ])['user'];

        for ($i = 0; $i < 5; $i++) {
            $this->withSession(['2fa_user_id' => $user->id])
                ->post(route('auth.two-factor.verify'), ['code' => '000000']);
        }

        $this->withSession(['2fa_user_id' => $user->id])
            ->post(route('auth.two-factor.verify'), ['code' => '000000'])
            ->assertStatus(429);
    }

    // ── Firebase ID token verification ──────────────────────────────────────

    public function test_firebase_rejects_tokens_not_issued_for_the_project(): void
    {
        [$privateKey, $cert] = $this->rsaKeyAndCert();
        Http::fake(['www.googleapis.com/robot/*' => Http::response(['kid1' => $cert])]);

        SystemSetting::set('firebase_enabled', 'true');
        SystemSetting::set('firebase_project_id', 'my-project');

        $victim = $this->createWorkspaceContext()['user'];

        // Correctly signed, but a plain Google sign-in token for another app.
        $foreign = JWT::encode([
            'iss' => 'https://accounts.google.com',
            'aud' => 'some-other-client-id',
            'sub' => 'attacker',
            'email' => $victim->email,
            'email_verified' => true,
            'iat' => time(),
            'exp' => time() + 3600,
        ], $privateKey, 'RS256', 'kid1');

        $this->postJson(route('auth.firebase'), ['id_token' => $foreign])->assertStatus(422);
        $this->assertGuest();

        // A genuine project token is accepted.
        $genuine = JWT::encode([
            'iss' => 'https://securetoken.google.com/my-project',
            'aud' => 'my-project',
            'sub' => 'firebase-uid-1',
            'email' => $victim->email,
            'email_verified' => true,
            'auth_time' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
        ], $privateKey, 'RS256', 'kid1');

        $this->postJson(route('auth.firebase'), ['id_token' => $genuine])
            ->assertOk()
            ->assertJson(['redirect' => route('client.dashboard')]);
        $this->assertAuthenticatedAs($victim);
    }

    // ── SSRF guard ──────────────────────────────────────────────────────────

    public function test_outbound_url_guard_blocks_internal_targets(): void
    {
        foreach ([
            'http://127.0.0.1/admin',
            'http://localhost:6379',
            'http://169.254.169.254/latest/meta-data/',
            'http://10.0.0.5/',
            'http://192.168.1.1/',
            'http://100.64.0.1/',
            'http://[::1]/',
            'http://[::ffff:127.0.0.1]/',
            'file:///etc/passwd',
            'gopher://example.com/',
            'http://user:pass@8.8.8.8/',
        ] as $url) {
            $this->assertNotNull(OutboundUrlGuard::check($url), "Expected {$url} to be blocked");
        }

        $this->assertNull(OutboundUrlGuard::check('https://8.8.8.8/hook'));
    }

    // ── Knowledge base: no arbitrary file read ──────────────────────────────

    public function test_kb_file_document_requires_an_actual_upload(): void
    {
        $ctx = $this->createWorkspaceContext();
        $kb = AiKnowledgeBase::create([
            'workspace_id' => $ctx['workspace']->id,
            'name' => 'KB',
            'embedding_model' => 'text-embedding-3-small',
            'dimensions' => 3,
            'status' => 'active',
        ]);

        $this->actingAs($ctx['user'])
            ->post(route('client.ai.knowledge-bases.documents.add', $kb), [
                'source_type' => 'file',
                'source_ref' => 'avatars/someone-elses-file.pdf',
            ])
            ->assertSessionHasErrors('file');

        $this->assertSame(0, $kb->documents()->count());
    }

    /** @return array{0: string, 1: string} [private key PEM, self-signed X.509 cert PEM] */
    private function rsaKeyAndCert(): array
    {
        $config = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
        if (getenv('OPENSSL_CONF') === false && is_file($cnf = dirname(PHP_BINARY).'/extras/ssl/openssl.cnf')) {
            $config['config'] = $cnf; // XAMPP / Windows builds ship without a default openssl.cnf
        }

        $key = openssl_pkey_new($config);
        $csr = openssl_csr_new(['commonName' => 'test'], $key, $config);
        $x509 = openssl_csr_sign($csr, null, $key, 1, $config);

        openssl_pkey_export($key, $privatePem, null, $config);
        openssl_x509_export($x509, $certPem);

        return [$privatePem, $certPem];
    }
}

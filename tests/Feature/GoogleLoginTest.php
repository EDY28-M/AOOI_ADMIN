<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class TestingGoogleClient extends \Google_Client
{
    public static array $payload = [];

    public function __construct(array $config = [])
    {
    }

    public function verifyIdToken($idToken = null)
    {
        return static::$payload;
    }
}

class GoogleLoginTest extends TestCase
{
    use RefreshDatabase;



    public function test_google_login_creates_user_by_google_id(): void
    {
        $payload = [
            'sub' => 'google123',
            'email' => 'user@example.com',
            'given_name' => 'User',
            'family_name' => 'Example',
            'picture' => 'http://example.com/avatar.png',
        ];

        $this->app->bind(\Google_Client::class, TestingGoogleClient::class);
        TestingGoogleClient::$payload = $payload;

        $response = $this->postJson('/api/auth/google_login', [
            'credential' => 'token',
        ]);

        $response->assertOk();
        $this->assertNotEmpty($response->json('access_token'));

        $this->assertDatabaseHas('users', [
            'google_id' => 'google123',
            'email' => 'user@example.com',
            'name' => 'User',
            'surname' => 'Example',
        ]);
    }

    public function test_google_login_updates_existing_user_by_google_id(): void
    {
        $user = User::factory()->create([
            'google_id' => 'google456',
            'email' => 'old@example.com',
            'name' => 'Old',
        ]);

        $payload = [
            'sub' => 'google456',
            'email' => 'new@example.com',
            'given_name' => 'New',
            'family_name' => 'Name',
            'picture' => 'http://example.com/new.png',
        ];

        $this->app->bind(\Google_Client::class, TestingGoogleClient::class);
        TestingGoogleClient::$payload = $payload;

        $response = $this->postJson('/api/auth/google_login', [
            'credential' => 'token2',
        ]);

        $response->assertOk();
        $this->assertNotEmpty($response->json('access_token'));

        $this->assertDatabaseCount('users', 1);

        $user->refresh();
        $this->assertSame('new@example.com', $user->email);
        $this->assertSame('New', $user->name);
        $this->assertSame('Name', $user->surname);
        $this->assertSame('google456', $user->google_id);
    }
}


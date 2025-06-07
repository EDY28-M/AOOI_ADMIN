<?php

namespace App\Http\Controllers;

use Validator;
use App\Models\User;
use App\Mail\VerifiedMail;
use Illuminate\Http\Request;
use App\Mail\ForgotPasswordMail;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Google_Client;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => [
            'login',
            'register',
            'login_ecommerce',
            'googleLogin',
            'verified_auth',
            'verified_email',
            'verified_code',
            'new_password',
        ]]);
    }

    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register()
    {
        $data = request()->only(['name', 'email', 'password']);
        $validator = Validator::make($data, [
            'name'     => 'required|string|max:255',
            'email'    => 'required|email|unique:users',
            'password' => 'required|string|min:6',
        ]);
        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors'  => $validator->errors()
            ], 422);
        }

        $user = new User;
        $user->name         = $data['name'];
        $user->type_user    = 2;               // Tipo Cliente
        $user->email        = $data['email'];
        $user->uniqd        = uniqid();
        $user->password     = bcrypt($data['password']);
        $user->save();

        $user->roles()->sync([1]); // Cliente

        return response()->json($user, 201);
    }

    /**
     * Get a JWT via given credentials for Admin.
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth('api')->attempt([
            'email'     => $credentials['email'],
            'password'  => $credentials['password'],
            'type_user' => 1
        ])) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get a JWT via given credentials for Cliente.
     */
    public function login_ecommerce()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth('api')->attempt([
            'email'     => $credentials['email'],
            'password'  => $credentials['password'],
            'type_user' => 2
        ])) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $user = auth('api')->user();
        if (! $user->email_verified_at) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Login or register with Google.
     */
    public function googleLogin(Request $request)
    {
        // 1) Validar que venga id_token
        $validator = Validator::make($request->only('id_token'), [
            'id_token' => 'required|string',
        ]);
        if ($validator->fails()) {
            return response()->json(['error' => 'id_token es requerido'], 422);
        }

        try {
            // 2) Verificar el token con Google
            $client = new Google_Client();
            $client->setClientId(config('services.google.client_id'));
            $payload = $client->verifyIdToken($request->id_token);

            if (! $payload) {
                return response()->json(['error' => 'Token de Google inválido'], 401);
            }

            // 3) Datos del usuario desde Google
            $email     = $payload['email'];
            $googleId  = $payload['sub'];
            $firstName = $payload['given_name']  ?? ($payload['name'] ?? '');
            $lastName  = $payload['family_name'] ?? '';
            $avatar    = $payload['picture']     ?? null;

            // 4) Buscar por email o crear/actualizar
            $user = User::where('email', $email)->first();
            if ($user) {
                // Si existe, solo asignamos google_id y marcamos email verificado
                $user->google_id         = $googleId;
                $user->email_verified_at = $user->email_verified_at ?: now();
                $user->avatar            = $avatar ?: $user->avatar;
                $user->save();
            } else {
                // Crear nuevo usuario
                $user = User::create([
                    'name'              => $firstName,
                    'surname'           => $lastName,
                    'email'             => $email,
                    'google_id'         => $googleId,
                    'avatar'            => $avatar,
                    'type_user'         => 2,                      // Cliente
                    'password'          => bcrypt(Str::random(16)),
                    'email_verified_at' => now(),
                    'uniqd'             => uniqid(),
                ]);
                $user->roles()->sync([1]); // Cliente
            }

            // 5) Generar JWT e devolver
            $token = auth('api')->login($user);
            return $this->respondWithToken($token);

        } catch (\Exception $e) {
            \Log::error('Error en googleLogin: ' . $e->getMessage());
            return response()->json(['error' => 'Error interno al autenticar con Google'], 500);
        }
    }

    /**
     * Get the authenticated User.
     */
    public function me()
    {
        $user = auth('api')->user();
        return response()->json([
            'name'         => $user->name,
            'surname'      => $user->surname,
            'phone'        => $user->phone,
            'email'        => $user->email,
            'bio'          => $user->bio,
            'fb'           => $user->fb,
            'sexo'         => $user->sexo,
            'address_city' => $user->address_city,
            'avatar'       => $user->avatar
                                ? env('APP_URL').'/storage/'.$user->avatar
                                : 'https://cdn-icons-png.flaticon.com/512/1476/1476614.png',
        ]);
    }

    /**
     * Get the authenticated User's permissions.
     */
    public function permissions()
    {
        if (! auth('api')->check()) {
            return response()->json(['error' => 'Unauthenticated'], 401);
        }

        $user = User::with('roles.permissions')->find(auth('api')->id());

        $allPermissions = [
            'manage-users'         => false,
            'manage-products'      => false,
            'manage-own-products'  => false,
        ];

        $roles = [];
        if ($user->type_user == 1) {
            $roles[] = 'Admin';
            foreach ($allPermissions as $key => $value) {
                $allPermissions[$key] = true;
            }
        } elseif ($user->type_user == 2) {
            $roles[] = 'Cliente';
            $allPermissions['manage-own-products'] = true;
        }

        return response()->json([
            'permissions' => $allPermissions,
            'roles'       => $roles
        ]);
    }

    /**
     * Log the user out (Invalidate the token).
     */
    public function logout()
    {
        auth('api')->logout();
        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     */
    public function refresh()
    {
        return $this->respondWithToken(auth('api')->refresh());
    }

    /**
     * Utility: Respond with token structure.
     */
    protected function respondWithToken($token)
    {
        $user = auth('api')->user();
        return response()->json([
            'access_token' => $token,
            'token_type'   => 'bearer',
            'expires_in'   => auth('api')->factory()->getTTL() * 60,
            'user'         => [
                'full_name' => $user->name . ' ' . $user->surname,
                'email'     => $user->email,
            ],
        ]);
    }

    // ... aquí quedan tus otros métodos: update, verified_email, verified_code, new_password, verified_auth, etc.
}

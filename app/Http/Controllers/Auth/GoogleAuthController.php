<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Google_Client;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Exception;

class GoogleAuthController extends Controller
{
    /**
     * Maneja la autenticación con Google.
     */
    public function handleGoogleCallback(Request $request)
    {
        // 1. Validar que el token venga en la petición
        $request->validate([
            'token' => 'required',
        ]);

        $idToken = $request->input('token');

        // 2. Verificar el idToken con Google
        $client = new Google_Client(['client_id' => env('GOOGLE_CLIENT_ID')]);
        try {
            $payload = $client->verifyIdToken($idToken);
        } catch (Exception $e) {
            Log::error("Error al verificar el token de Google: " . $e->getMessage());
            return response()->json(['error' => 'Token inválido o expirado.'], 401);
        }

        if ($payload) {
            // 3. El token es válido, obtenemos los datos del usuario
            $googleId = $payload['sub'];
            $email = $payload['email'];
            $name = $payload['name'];
            $avatar = $payload['picture'] ?? null;

            // 4. Buscamos o creamos al usuario en nuestra base de datos
            // Usamos updateOrCreate para manejar tanto registros nuevos como existentes.
            $user = User::updateOrCreate(
                ['google_id' => $googleId],
                [
                    'email' => $email,
                    'name' => $name,
                    'avatar' => $avatar,
                    'type_user' => 'CLIENT',
                    'email_verified_at' => now(),
                    'password' => bcrypt(str()->random(16))
                ]
            );

            // 5. Creamos un token JWT para nuestro sistema
            // Asegúrate de tener una librería como tymon/jwt-auth configurada
            if (!$token = auth('api')->login($user)) {
                 return response()->json(['error' => 'No se pudo crear el token.'], 500);
            }

            // 6. Devolvemos el token JWT y los datos del usuario
            return $this->respondWithToken($token, $user);

        } else {
            // El token no es válido
            return response()->json(['error' => 'Token de Google inválido.'], 401);
        }
    }

    /**
     * Formatea la respuesta con el token JWT.
     */
    protected function respondWithToken($token, $user)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60, // tiempo en segundos
            'user' => $user // Devuelve los datos del usuario
        ]);
    }
}
<?php

namespace App\Http\Controllers;

use Validator;
use App\Models\User;
use App\Mail\VerifiedMail;
use Illuminate\Http\Request;
use App\Mail\ForgotPasswordMail;
use App\Http\Controllers\Controller;
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
    public function register() {
        $validator = Validator::make(request()->all(), [
            'name' => 'required',
            'surname' => 'required',
            'phone' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:8',
        ]);
 
        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }
 
        $user = new User;
        $user->name = request()->name;
        $user->surname = request()->surname;
        $user->phone = request()->phone;
        $user->type_user = 2;
        $user->email = request()->email;
        $user->uniqd = uniqid();
        $user->password = bcrypt(request()->password);
        $user->save();

        Mail::to(request()->email)->send(new VerifiedMail($user));

        return response()->json($user, 201);
    }
    
    public function update(Request $request) {
        if($request->passowrd){
            $user = User::find(auth("api")->user()->id);
            $user->update([
                "password" => bcrypt($request->password)
            ]);
            return response()->json([
                "message" => 200,
            ]);
        }
        $is_exists_email = User::where("id","<>",auth("api")->user()->id)
                                    ->where("email",$request->email)->first();
        if($is_exists_email){
            return response()->json([
                "message" => 403,
                "message_text" => "El usuario ya existe"
            ]);
        }
        $user = User::find(auth("api")->user()->id);
        if($request->hasFile("file_imagen")){
            if($user->avatar){
                Storage::delete($user->avatar);
            }
            $path = Storage::putFile("users",$request->file("file_imagen"));
            $request->request->add(["avatar" => $path]);
        }
        $user->update($request->all());
        return response()->json([
            "message" => 200,
        ]);
    }

    public function verified_email(Request $request){
        $user = User::where("email",$request->email)->first();
        if($user){
            $user->update(["code_verified" => uniqid()]);
            Mail::to($request->email)->send(new ForgotPasswordMail($user));
            return response()->json(["message" => 200]);
        }else{
            return response()->json(["message" => 403]);
        }
    }
    public function verified_code(Request $request){
        $user = User::where("code_verified",$request->code)->first();
        if($user){
            return response()->json(["message" => 200]);
        }else{
            return response()->json(["message" => 403]);
        }
    }
    public function new_password(Request $request){
        $user = User::where("code_verified",$request->code)->first();
        $user->update(["password" => bcrypt($request->new_password),"code_verified" => null]);
        return response()->json(["message" => 200]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);
 
        if (! $token = auth('api')->attempt([
            "email" => request()->email,
            "password" => request()->password,
            "type_user" => 1])) {
            
            // Intentar también con "ADMIN" como tipo de usuario
            if (! $token = auth('api')->attempt([
                "email" => request()->email,
                "password" => request()->password,
                "type_user" => "ADMIN"])) {
                return response()->json(['error' => 'Unauthorized'], 401);
            }
        }
 
        return $this->respondWithToken($token);
    }

    public function login_ecommerce()
    {
        $credentials = request(['email', 'password']);
 
        if (! $token = auth('api')->attempt([
            "email" => request()->email,
            "password" => request()->password,
            "type_user" => 2])) {
            
            // Intentar también con "CLIENT" como tipo de usuario
            if (! $token = auth('api')->attempt([
                "email" => request()->email,
                "password" => request()->password,
                "type_user" => "CLIENT"])) {
                return response()->json(['error' => 'Unauthorized'], 401);
            }
        }

        if(!auth('api')->user()->email_verified_at){
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    public function googleLogin(Request $request)
    {
        $client = app(Google_Client::class, [
            'config' => ['client_id' => config('services.google.client_id')],
        ]);
        $payload = $client->verifyIdToken($request->credential);

        if (!$payload) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $googleId = $payload['sub'];

        $user = User::updateOrCreate(
            ['google_id' => $googleId],
            [
                'email' => $payload['email'],
                'name' => $payload['given_name'] ?? $payload['name'] ?? '',
                'surname' => $payload['family_name'] ?? '',
                'avatar' => $payload['picture'] ?? null,
                'type_user' => 2,
                'password' => bcrypt(Str::random(16)),
                'email_verified_at' => now(),
            ]
        );

        $token = auth('api')->login($user);

        return $this->respondWithToken($token);
    }
    
    public function verified_auth(Request $request){
        $user = User::where("uniqd", $request->code_user)->first();

        if($user){
            $user->update(["email_verified_at" => now()]);
            return response()->json(["message" => 200]);
        }

        return response()->json(["message" => 403]);
    }
    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        $user = User::find(auth("api")->user()->id);
        return response()->json([
            'name' => $user->name,
            'surname' => $user->surname,
            'phone' => $user->phone,
            'email' => $user->email,
            'bio' => $user->bio,
            'fb' => $user->fb,
            'sexo' => $user->sexo,
            'address_city' => $user->address_city,
            'avatar' => $user->avatar ? env("APP_URL")."storage/".$user->avatar : 'https://cdn-icons-png.flaticon.com/512/1476/1476614.png',
        ]);
    }

    /**
     * Get the authenticated User's permissions.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function permissions()
    {
        if (!auth('api')->check()) {
            return response()->json(['error' => 'Unauthenticated'], 401);
        }

        $user = User::with('roles.permissions')->find(auth('api')->user()->id);
        
        // Lista de todos los permisos posibles
        $allPermissions = [
            'manage-users' => false,
            'manage-products' => false,
            'manage-own-products' => false,
            // Puedes añadir más permisos aquí
        ];
        
        // Marcar los permisos que el usuario tiene
        foreach ($user->roles as $role) {
            if ($role->name === 'Admin') {
                // El rol Admin tiene todos los permisos
                foreach ($allPermissions as $key => $value) {
                    $allPermissions[$key] = true;
                }
                break;
            }
            
            foreach ($role->permissions as $permission) {
                if (isset($allPermissions[$permission->name])) {
                    $allPermissions[$permission->name] = true;
                }
            }
        }
        
        // Registrar en log para depuración
        \Illuminate\Support\Facades\Log::info('User permissions', [
            'user_id' => $user->id,
            'permissions' => $allPermissions,
            'roles' => $user->roles->pluck('name')
        ]);
        
        return response()->json([
            'permissions' => $allPermissions,
            'roles' => $user->roles->pluck('name')
        ]);
    }
 
    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth('api')->logout();
 
        return response()->json(['message' => 'Successfully logged out']);
    }
 
    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth('api')->refresh());
    }
 
    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60,
            "user" => [
                "full_name" => auth('api')->user()->name . ' ' . auth('api')->user()->surname,
                "email" => auth('api')->user()->email,
            ],
        ]);
    }
}

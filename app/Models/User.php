<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use App\Models\Sale\Cart;
use App\Models\Sale\UserAddres;
use Laravel\Sanctum\HasApiTokens;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Notifications\Notifiable;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable implements JWTSubject
{
    use HasApiTokens, HasFactory, Notifiable, SoftDeletes;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'surname',
        'type_user',
        'avatar',
        'phone',
        'email',
        'google_id',
        "uniqd",
        "code_verified",
        'password',
        "email_verified_at",

        "address_city",
        "bio",
        "fb",
        "sexo"
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed',
    ];

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }
 
    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }

    public function carts(){
        return $this->hasMany(Cart::class,"user_id");
    }

    public function address(){
        return $this->hasMany(UserAddres::class,"user_id");
    }

    /**
     * The roles that belong to the user.
     */
    public function roles()
    {
        return $this->belongsToMany(Role::class);
    }

    /**
     * Check if the user has a specific role
     */
    public function hasRole($roleName)
    {
        return $this->roles()->where('name', $roleName)->exists();
    }

    /**
     * Check if the user has any permission through their roles
     */
    public function hasPermission($permissionName)
    {
        // Optimización: Si es Admin, tiene todos los permisos
        if ($this->hasRole('Admin')) {
            return true;
        }
        
        // Verificar en todos los roles del usuario
        foreach ($this->roles as $role) {
            if ($role->permissions()->where('name', $permissionName)->exists()) {
                return true;
            }
        }
        
        return false;
    }
}

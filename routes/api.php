<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\Admin\SliderController;
use App\Http\Controllers\Ecommerce\CartController;
use App\Http\Controllers\Ecommerce\HomeController;
use App\Http\Controllers\Ecommerce\SaleController;
use App\Http\Controllers\Admin\Sale\SalesController;
use App\Http\Controllers\Ecommerce\ReviewController;
use App\Http\Controllers\Admin\Cupone\CuponeController;
use App\Http\Controllers\Admin\Product\BrandController;
use App\Http\Controllers\Admin\Product\ProductController;
use App\Http\Controllers\Ecommerce\UserAddressController;
use App\Http\Controllers\Admin\Discount\DiscountController;
use App\Http\Controllers\Admin\Product\CategorieController;
use App\Http\Controllers\Admin\Sale\KpiSaleReportController;
use App\Http\Controllers\Admin\Product\AttributeProductController;
use App\Http\Controllers\Admin\Product\ProductVariationsController;
use App\Http\Controllers\Admin\Product\ProductSpecificationsController;
use App\Http\Controllers\Admin\Product\ProductVariationsAnidadoController;
use App\Http\Controllers\Admin\UserController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });
Route::group([
    // 'middleware' => 'auth:api',
    'prefix' => 'auth'
], function ($router) {
    Route::post('/register', [AuthController::class, 'register'])->name('register');
    Route::post('/login', [AuthController::class, 'login'])->name('login');
    Route::post('/login_ecommerce', [AuthController::class, 'login_ecommerce'])->name('login_ecommerce');
    Route::post('/google_login', [AuthController::class, 'googleLogin'])->name('google_login');
    Route::post('/logout', [AuthController::class, 'logout'])->name('logout');
    Route::post('/refresh', [AuthController::class, 'refresh'])->name('refresh');
    Route::post('/me', [AuthController::class, 'me'])->name('me');
    Route::post('/permissions', [AuthController::class, 'permissions'])->name('permissions');
    Route::post('/verified_auth', [AuthController::class, 'verified_auth'])->name('verified_auth');
    Route::post('/login-json', [\App\Http\Controllers\AuthController::class, 'loginJson'])->name('login_json');
    Route::post('/verified_email', [AuthController::class, 'verified_email'])->name('verified_email');
    Route::post('/verified_code', [AuthController::class, 'verified_code'])->name('verified_code');
    Route::post('/new_password', [AuthController::class, 'new_password'])->name('new_password');
});

Route::group([
    "middleware" => "auth:api",
    "prefix" => "admin",
],function ($router) {
    // Rutas accesibles para usuarios con permiso manage-users o rol Admin
    Route::middleware(['permission:manage-users'])->group(function () {
        Route::post("users-list", [App\Http\Controllers\Admin\UserController::class, "index"]);
        Route::apiResource("users", App\Http\Controllers\Admin\UserController::class);
        Route::post("users/{user_id}/roles/{role_id}", [App\Http\Controllers\Admin\UserController::class, "assignRole"]);
        Route::delete("users/{user_id}/roles/{role_id}", [App\Http\Controllers\Admin\UserController::class, "removeRole"]);
        
        Route::post("roles-list", [App\Http\Controllers\Admin\RoleController::class, "index"]);
        Route::post("roles/{id}/users", [App\Http\Controllers\Admin\RoleController::class, "getUsers"]);
        Route::delete("roles/{role_id}/users/{user_id}", [App\Http\Controllers\Admin\RoleController::class, "deleteUser"]);
        Route::apiResource("roles", App\Http\Controllers\Admin\RoleController::class);
        
        Route::post("permissions-list", [App\Http\Controllers\Admin\PermissionController::class, "index"]);
        Route::apiResource("permissions", App\Http\Controllers\Admin\PermissionController::class);
    });
    
    // Rutas de productos - accesibles para todos los usuarios autenticados
    // pero el controlador filtrará según permisos
    Route::middleware(['permission:manage-products|manage-own-products'])->group(function () {
        Route::get("products/config", [ProductController::class, "config"]);
        Route::post("products/index", [ProductController::class, "index"]);
        Route::post("products", [ProductController::class, "store"])->middleware('product.limit');
        Route::get("products/{id}", [ProductController::class, "show"]);
        Route::post("products/{id}", [ProductController::class, "update"]);
        Route::delete("products/{id}", [ProductController::class, "destroy"]);
        
        // Rutas para gestionar imágenes de productos
        Route::post("products/imagens", [ProductController::class, "imagens"]);
        Route::delete("products/imagens/{id}", [ProductController::class, "delete_imagen"]);
        
        // Rutas de categorías - también accesibles para usuarios con permisos de productos
        Route::get("categories/config", [CategorieController::class, "config"]);
        Route::get("categories", [CategorieController::class, "index"]);
        Route::post("categories", [CategorieController::class, "store"]);
        Route::get("categories/{id}", [CategorieController::class, "show"]);
        Route::post("categories/{id}", [CategorieController::class, "update"]);
        Route::delete("categories/{id}", [CategorieController::class, "destroy"]);
        
        // Ruta de configuración de KPI (solo configuración básica)
        Route::get("kpi/config", [KpiSaleReportController::class, "config"]);
    });
    
    // Rutas accesibles solo para administradores
    Route::middleware(['permission:manage-products'])->group(function () {

        Route::post("properties", [AttributeProductController::class, "store_propertie"]);
        Route::delete("properties/{id}", [AttributeProductController::class, "destroy_propertie"]);
        Route::resource("attributes", AttributeProductController::class);

        Route::resource("sliders", SliderController::class);
        Route::post("sliders/{id}", [SliderController::class, "update"]);

        Route::resource("brands", BrandController::class);

        Route::get("variations/config", [ProductVariationsController::class, "config"]);
        Route::resource("variations", ProductVariationsController::class);
        Route::resource("anidado_variations", ProductVariationsAnidadoController::class);

        Route::resource("specifications", ProductSpecificationsController::class);

        Route::get("cupones/config", [CuponeController::class, "config"]);
        Route::resource("cupones", CuponeController::class);

        Route::resource("discounts", DiscountController::class);

        Route::post("sales/list", [SalesController::class, "list"]);

        // Rutas específicas de KPI para reportes avanzados
        Route::group([
            "prefix" => "kpi",
        ],function ($router) {
            Route::post("report_sales_country_for_year", [KpiSaleReportController::class, "report_sales_country_for_year"]);
            Route::post("report_sales_week_categorias", [KpiSaleReportController::class, "report_sales_week_categorias"]);
            Route::post("report_sales_week_discounts", [KpiSaleReportController::class, "report_sales_week_discounts"]);
            Route::post("report_sales_month_selected", [KpiSaleReportController::class, "report_sales_month_selected"]);
            Route::post("report_sales_for_month_year_selected", [KpiSaleReportController::class, "report_sales_for_month_year_selected"]);
            Route::post("report_discount_cupone_year", [KpiSaleReportController::class, "report_discount_cupone_year"]);
            Route::post("report_sales_for_categories", [KpiSaleReportController::class, "report_sales_for_categories"]);
            Route::post("report_sales_for_categories_details", [KpiSaleReportController::class, "report_sales_for_categories_details"]);
            Route::post("report_sales_for_brand", [KpiSaleReportController::class, "report_sales_for_brand"]);
        });
    });
});

Route::get("sales/list-excel",[SalesController::class,"list_excel"]);
Route::get("sales/report-pdf/{id}",[SalesController::class,"report_pdf"]);

Route::group([
    "prefix" => "ecommerce",
],function ($router) {
    Route::get("home",[HomeController::class,"home"]);
    Route::get("menus",[HomeController::class,"menus"]);

    Route::get("product/{slug}",[HomeController::class,"show_product"]);
    Route::get("config-filter-advance",[HomeController::class,"config_filter_advance"]);
    Route::post("filter-advance-product",[HomeController::class,"filter_advance_product"]);
    Route::post("campaing-discount-link",[HomeController::class,"campaing_discount_link"]);

    Route::group([
        "middleware" => 'auth:api',
    ],function($router) {
        Route::delete("carts/delete_all",[CartController::class,"delete_all"]);
        Route::post("carts/apply_cupon",[CartController::class,"apply_cupon"]);
        Route::resource('carts', CartController::class);
        Route::resource('user_address', UserAddressController::class);
        
        Route::get("mercadopago",[SaleController::class,"mercadopago"]);
        Route::get("sale/{id}",[SaleController::class,"show"]);
        Route::post("checkout",[SaleController::class,"store"]);
        Route::post("checkout-temp",[SaleController::class,"checkout_temp"]);
        Route::post("checkout-mercadopago",[SaleController::class,"checkout_mercadopago"]);
        
        Route::get("profile_client/me",[AuthController::class,"me"]);
        Route::get("profile_client/orders",[SaleController::class,"orders"]);
        Route::post("profile_client",[AuthController::class,"update"]);
        Route::resource('reviews', ReviewController::class);

    });

});

Route::post('/users', [UserController::class, 'store']);
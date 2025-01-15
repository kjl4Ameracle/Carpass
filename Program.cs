using Carpass_Profilling.Components;
using Carpass_Profilling.Data;
using Carpass_Profilling.Service;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Syncfusion.Blazor;
using Carpass_Profilling.Components.Middleware;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Configure Kestrel server options
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 5 * 1024 * 1024; // 5 MB
});

// Register Syncfusion license
Syncfusion.Licensing.SyncfusionLicenseProvider.RegisterLicense("MzQwMTYwNkAzMjM2MmUzMDJlMzBCVXVVVTVLeHRVVmRhMklUUTBZS3NJQ21JVDI1dEtnUjJBRlhJc3VrQlE4PQ==");

// Add services to the container
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddControllers();
builder.Services.AddAntiforgery();

builder.Services.AddDbContext<DataContext>(options =>
    options.UseMySql(builder.Configuration.GetConnectionString("DefaultConnection"),
        ServerVersion.AutoDetect(builder.Configuration.GetConnectionString("DefaultConnection"))));

// Authentication and Authorization
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/accessdenied";
        options.Cookie.IsEssential = true;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = true;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AllowAnonymous", policy => policy.RequireAssertion(context => true));
    options.FallbackPolicy = options.DefaultPolicy;
});

builder.Services.AddScoped<AuthenticationStateProvider, ServerAuthenticationStateProvider>();

// Dependency Injection for Services
builder.Services.AddScoped<ISchoolYearService, SchoolYearService>();
builder.Services.AddScoped<IApplicantService, ApplicantService>();
builder.Services.AddScoped<IPendingService, PendingService>();
builder.Services.AddScoped<ICentralDataService, CentralDataService>();
builder.Services.AddScoped<UserService>();
builder.Services.AddHttpContextAccessor();



builder.Services.AddSyncfusionBlazor();

builder.Services.AddServerSideBlazor()
    .AddCircuitOptions(options => { options.DetailedErrors = true; });

var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

// Authentication and Authorization middleware
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<AuthMiddleware>();

// Anti-forgery Middleware
app.UseAntiforgery();

// Map controllers
app.MapControllers();

// Map Razor Components
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

// Custom ServerAuthenticationStateProvider
public class ServerAuthenticationStateProvider : AuthenticationStateProvider
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public ServerAuthenticationStateProvider(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var identity = _httpContextAccessor.HttpContext?.User.Identity as ClaimsIdentity;
        var user = new ClaimsPrincipal(identity ?? new ClaimsIdentity());
        return Task.FromResult(new AuthenticationState(user));
    }
}
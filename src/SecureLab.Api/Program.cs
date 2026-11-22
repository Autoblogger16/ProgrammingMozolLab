using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using System.Threading.RateLimiting;
using SecureLab.Api.Scaffolding;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Endpoints;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = "Client"
});
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

var connectionString = builder.Configuration.GetConnectionString("SecureLab")
    ?? throw new InvalidOperationException(
        "Connection string 'SecureLab' не налаштовано.");

builder.Services.AddDbContext<SecureLabDbContext>(options =>
    options.UseNpgsql(connectionString));
builder.Services.AddScoped<IncidentQueries>();

// Обмеження частоти запитів: login (з ЛР 3) і search (ЛР 6).
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // Подія відхиленого запиту: лише результат, шлях і traceId — без логіна, пароля, cookie.
    options.OnRejected = (context, _) =>
    {
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogWarning("Rate limit event: result {Result}, path {Path}, trace {TraceId}",
            "rate_limited", context.HttpContext.Request.Path, context.HttpContext.TraceIdentifier);
        return ValueTask.CompletedTask;
    };

    // Login (ЛР 3, без змін): ключ — IP клієнта; у тестовому сервері IP немає, тому "unknown".
    options.AddPolicy("login", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromSeconds(30),
                QueueLimit = 0
            }));

    // ЛР 6: пошук — окрема квота для кожного користувача (id з cookie), для аноніма — за IP.
    // 5 запитів за 10 секунд, без черги.
    options.AddPolicy("search", httpContext =>
    {
        var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var key = userId is not null
            ? $"user:{userId}"
            : $"ip:{httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown"}";
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: key,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromSeconds(10),
                QueueLimit = 0
            });
    });
});

builder.AddLab03Identity();
// ЛР 5: CORS policy лише для Development і лише для probe 4173.
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("Lab05BrowserProbe", policy =>
        {
            policy.WithOrigins("http://localhost:4173")
                .WithMethods("GET")
                .WithHeaders("X-Lab-Cors-Probe")
                .AllowCredentials();
        });
    });
}
// ЛР 6: antiforgery. Контракт сервер ↔ клієнт: request token передається в header X-CSRF-TOKEN.
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "securelab-af";
});

var app = builder.Build();

var resetRequested = args.Contains("--reset-database", StringComparer.Ordinal);
await DatabaseBootstrap.InitializeAsync(app.Services, app.Configuration, app.Environment, resetRequested);

if (resetRequested)
{
    return;
}

app.UseExceptionHandler();
app.UseStatusCodePages();

// ЛР 5: CSP за зразком методички; усі ресурси клієнта лише з власного origin.
var csp = "default-src 'self'; frame-ancestors 'none'";

app.Use(async (context, next) =>
{
    // Development-довідник /scalar має власні ресурси стороннього пакета,
    // тому CSP основного клієнта до нього не застосовується.
    var isDevelopmentApiReference =
        app.Environment.IsDevelopment()
        && context.Request.Path.StartsWithSegments("/scalar");

    // ЛР 6, F-01: ExceptionHandlerMiddleware очищає заголовки перед записом 500,
    // тому заголовки безпеки ставимо в момент надсилання відповіді через OnStarting,
    // і вони потрапляють також у відповіді з помилками.
    context.Response.OnStarting(() =>
    {
        var headers = context.Response.Headers;
        headers.XContentTypeOptions = "nosniff";
        headers["Referrer-Policy"] = "no-referrer";
        if (!isDevelopmentApiReference)
        {
            headers.ContentSecurityPolicy = csp;
        }
        return Task.CompletedTask;
    });

    await next(context);
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}
app.UseRouting();
if (app.Environment.IsDevelopment())
{
    app.UseCors("Lab05BrowserProbe");
}
app.UseAuthentication();
app.UseAuthorization();

app.UseRateLimiter();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", async (SecureLabDbContext dbContext, CancellationToken cancellationToken) =>
    await dbContext.Database.CanConnectAsync(cancellationToken)
        ? Results.Ok(new { status = "ready" })
        : Results.Problem(
            title: "База даних недоступна",
            statusCode: StatusCodes.Status503ServiceUnavailable))
    .WithName("GetHealth")
    .Produces(StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

// ЛР 6: видача antiforgery-токена. Cookie-частина йде в Set-Cookie, request token — у JSON.
// Лише для автентифікованого користувача: токен прив'язано до поточного principal.
app.MapGet("/api/auth/csrf-token", (IAntiforgery antiforgery, HttpContext http) =>
{
    var tokens = antiforgery.GetAndStoreTokens(http);
    return Results.Ok(new { token = tokens.RequestToken });
}).RequireAuthorization();

app.MapIncidentEndpoints();
app.MapLab03Identity();
app.MapLab04Endpoints();
app.MapLab02Endpoints();
app.MapFallbackToFile("index.html");

app.Run();

public partial class Program;
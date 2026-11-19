using System.Security.Claims; 
using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        // ===== ЛР 3, етап 2: POST /api/auth/register — ПОЧАТОК =====
        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
            // 1. Обов'язкові поля. Пароль перевіряємо як є, без Trim.
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrWhiteSpace(input.Email)
                || string.IsNullOrWhiteSpace(input.DisplayName) || string.IsNullOrEmpty(input.Password))
                return RegistrationFailed();

            // 2. Нормалізуємо лише профільні поля; пароль не змінюємо і ніде не логуємо.
            var userName = input.UserName.Trim();
            var email = input.Email.Trim();
            var displayName = input.DisplayName.Trim();

            // 3. Довжина й формат за контрактом (межі з моделі: DisplayName 120, Email 256).
            if (userName.Length is < 3 or > 64
                || !userName.All(c => char.IsAsciiLetterOrDigit(c) || "-._@+".Contains(c))
                || email.Length > 256 || !email.Contains('@')
                || displayName.Length > 120
                || input.Password.Length > 128)
                return RegistrationFailed();

            // 4. Хеш пароля обчислює сам Identity всередині CreateAsync.
            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = userName,
                Email = email,
                DisplayName = displayName
            };
            var result = await users.CreateAsync(user, input.Password);
            if (!result.Succeeded)
            {
                // 5. Дублікат імені або email -> 409, усе інше -> однаковий 400.
                var duplicate = result.Errors.Any(e => e.Code is "DuplicateUserName" or "DuplicateEmail");
                return duplicate
                    ? Results.Conflict(new { message = "Account already exists" })
                    : RegistrationFailed();
            }

            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");

            // 6. Лише затверджені поля відповіді.
            return Results.Created("/api/me", new RegistrationResponse(user.Id, userName, displayName));
        });
        // ===== ЛР 3, етап 2: POST /api/auth/register — КІНЕЦЬ =====

        // Login з подіями автентифікації і обмеженням спроб "login".
        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn,
            HttpContext httpContext, ILogger<Program> logger) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
            {
                logger.LogInformation("Auth event {EventType}: result {Result}, trace {TraceId}",
                    "login", "failure", httpContext.TraceIdentifier);
                return Results.Unauthorized();
            }
            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);

            // Подія: лише тип, результат і traceId — без логіна, пароля, cookie чи тіла запиту.
            logger.LogInformation("Auth event {EventType}: result {Result}, trace {TraceId}",
                "login", result.Succeeded ? "success" : "failure", httpContext.TraceIdentifier);

            // Відповідь для невідомого користувача і хибного пароля однакова: 401.
            return result.Succeeded ? Results.NoContent() : Results.Unauthorized();
        }).RequireRateLimiting("login");


        // Logout з подією: id береться з principal до виходу; інших даних у подію не потрапляє.
        app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn,
            HttpContext httpContext, ILogger<Program> logger) =>
        {
            var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "anonymous";
            await signIn.SignOutAsync();
            logger.LogInformation("Auth event {EventType}: user {UserId}, result {Result}, trace {TraceId}",
                "logout", userId, "success", httpContext.TraceIdentifier);
            return Results.NoContent();
        });

        app.MapGet("/api/me", (HttpContext context) =>
        {
            var principal = context.User;
            if (!Guid.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
                return Results.Unauthorized();

            var userName = principal.Identity?.Name ?? "";
            var role = principal.FindFirstValue(ClaimTypes.Role) ?? "";
            return Results.Ok(new MeResponse(userId, userName, role));
        }).RequireAuthorization();


        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }

    // ===== ЛР 3, етап 2: однакова безпечна відмова register — ПОЧАТОК =====
    // Не розкриває, яке саме поле або правило не пройшло.
    private static IResult RegistrationFailed() =>
        Results.BadRequest(new { message = "Registration failed" });
    // ===== ЛР 3, етап 2: однакова безпечна відмова register — КІНЕЦЬ =====
}
public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);

// ===== ЛР 3, етап 2: response DTO для register — ПОЧАТОК =====
// Лише безпечні поля: без пароля, хешу, ролі чи службових даних.
public sealed record RegistrationResponse(Guid Id, string UserName, string DisplayName);
// ===== ЛР 3, етап 2: response DTO для register — КІНЕЦЬ =====


// Лише дозволені поля профілю з principal: без пароля, хешу, email чи cookie.
public sealed record MeResponse(Guid Id, string UserName, string Role);

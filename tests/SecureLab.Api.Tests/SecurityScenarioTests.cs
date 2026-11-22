using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// Безпекові сценарії ЛР 3: A-01 … A-07.
public sealed class SecurityScenarioTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    // Пароль навчальних акаунтів лише зі змінної середовища, не з коду.
    private static string Password =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Клієнт без входу: не йде за редиректом, тому видно справжній статус.
    private HttpClient CreateAnonymousClient() =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

    // Фактичний власник інциденту з БД (а не з відповіді, яку формує endpoint).
    private async Task<Guid> GetOwnerAsync(Guid incidentId)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.AsNoTracking()
            .Where(item => item.Id == incidentId)
            .Select(item => item.OwnerUserId)
            .SingleAsync();
    }

    private async Task DeleteIncidentAsync(Guid incidentId)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Id == incidentId).ExecuteDeleteAsync();
    }

    private static async Task<Guid> ReadIdAsync(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("id").GetGuid();
    }

    // A-01: анонімний запит до захищеного endpoint -> 401, а не redirect чи HTML.
    [Fact]
    public async Task A01_AnonymousCreate_Returns401NotRedirect()
    {
        using var client = CreateAnonymousClient();

        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"A01-{Guid.NewGuid():N}",
            description = "Анонімний запит",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);                 // немає 302 redirect
        Assert.Empty(response.Headers.WwwAuthenticate);         // немає Bearer challenge
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    // A-02: після входу /api/me повертає поточного користувача з cookie і лише дозволені поля.
    [Fact]
    public async Task A02_LoginThenMe_ReturnsCurrentUserFromCookie()
    {
        using var client = await factory.LoginAsync("alice", Password);

        using var response = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        Assert.Equal(DbSeeder.AliceId, root.GetProperty("id").GetGuid());
        Assert.Equal("alice", root.GetProperty("userName").GetString());

        var fields = root.EnumerateObject().Select(p => p.Name.ToLowerInvariant()).ToList();
        Assert.DoesNotContain(fields, f =>
            f.Contains("password") || f.Contains("hash") || f.Contains("stamp") || f.Contains("email"));
    }

    // A-03: valid cookie Alice + X-Demo-UserId Боба -> /api/me все одно повертає Alice.
    [Fact]
    public async Task A03_ForeignDemoHeader_DoesNotChangeCurrentUser()
    {
        using var client = await factory.LoginAsync("alice", Password);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceId, doc.RootElement.GetProperty("id").GetGuid());
    }

    // A-04: Bob створює інцидент без owner у DTO -> власник Bob (з principal).
    [Fact]
    public async Task A04_CreateWithoutOwner_SetsOwnerFromPrincipal()
    {
        using var client = await factory.LoginAsync("bob", Password);

        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"A04-{Guid.NewGuid():N}",
            description = "Створено Бобом без поля власника",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var id = await ReadIdAsync(response);
        try
        {
            Assert.Equal(DbSeeder.BobId, await GetOwnerAsync(id));
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // A-05: Bob надсилає чужий ownerUserId (Alice) -> поле ігнорується, власник лишається Bob.
    [Fact]
    public async Task A05_ForeignOwnerInJson_IsIgnored()
    {
        using var client = await factory.LoginAsync("bob", Password);

        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"A05-{Guid.NewGuid():N}",
            description = "Спроба підставити чужого власника",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
            ownerUserId = DbSeeder.AliceId
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var id = await ReadIdAsync(response);
        try
        {
            var owner = await GetOwnerAsync(id);
            Assert.Equal(DbSeeder.BobId, owner);
            Assert.NotEqual(DbSeeder.AliceId, owner);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // A-06: після logout той самий клієнт отримує 401 на /api/me.
    [Fact]
    public async Task A06_Logout_ThenMeReturns401()
    {
        using var client = await factory.LoginAsync("alice", Password);

        using var before = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        using var logout = await client.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        using var after = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    // A-07: невідомий користувач і хибний пароль дають однаковий зовнішній результат.
    [Fact]
    public async Task A07_UnknownUserAndWrongPassword_LookTheSame()
    {
        using var client = CreateAnonymousClient();

        using var unknown = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = $"nobody-{Guid.NewGuid():N}", password = Password });
        using var wrong = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = Password + "-wrong" });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(unknown.StatusCode, wrong.StatusCode);
        Assert.Equal(unknown.Content.Headers.ContentType?.MediaType, wrong.Content.Headers.ContentType?.MediaType);

        // Порівнюємо стабільні поля (traceId може відрізнятися, тому його не порівнюємо).
        Assert.Equal(await StableShapeAsync(unknown), await StableShapeAsync(wrong));
    }

    // Cookie flags: вхід через HTTPS ставить cookie сеансу з HttpOnly, Secure, SameSite=Lax.
    [Fact]
    public async Task CookieFlags_LoginOverHttps_SetsSecureAttributes()
    {
        using var client = CreateAnonymousClient();   // HTTPS-клієнт (https://localhost)

        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = Password });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        // Беремо лише основну cookie сеансу; її значення не читаємо і не друкуємо.
        const string sessionCookie = ".AspNetCore.Identity.Application=";
        var session = response.Headers.GetValues("Set-Cookie")
            .Where(value => value.StartsWith(sessionCookie, StringComparison.Ordinal))
            .ToList();
        Assert.True(session.Count == 1, "Очікувалась рівно одна cookie сеансу.");

        // Розбираємо лише атрибути після першого ';'.
        var attributes = session[0].Split(';').Skip(1)
            .Select(part => part.Trim().ToLowerInvariant())
            .ToList();

        Assert.Contains("httponly", attributes);        // JavaScript не може прочитати cookie
        Assert.Contains("secure", attributes);          // передається лише через HTTPS
        Assert.Contains("samesite=lax", attributes);    // обмежує частину cross-site надсилань
        Assert.Contains("path=/", attributes);
        Assert.DoesNotContain(attributes, a => a.StartsWith("expires=", StringComparison.Ordinal)); // сеансова cookie
    }

    // Rate limit: 10 невдалих входів у межах вікна дають 401, 11-й — 429; після вікна вхід знову дозволено.
    [Fact]
    public async Task RateLimit_Login_Returns429ThenRecoversAfterWindow()
    {
        // Окремий host: лічильник ліміту належить host, тож інші тести на нього не впливають.
        using var host = factory.WithWebHostBuilder(_ => { });
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        var wrong = new { userName = "alice", password = Password + "-wrong" };

        // 10 спроб у межах ліміту: звичайна відмова 401.
        for (var i = 0; i < 10; i++)
        {
            using var attempt = await client.PostAsJsonAsync("/api/auth/login", wrong);
            Assert.Equal(HttpStatusCode.Unauthorized, attempt.StatusCode);
        }

        // 11-та спроба: 429 і для існуючого, і для неіснуючого акаунта.
        using var limitedExisting = await client.PostAsJsonAsync("/api/auth/login", wrong);
        using var limitedUnknown = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = $"nobody-{Guid.NewGuid():N}", password = Password + "-x" });
        Assert.Equal(HttpStatusCode.TooManyRequests, limitedExisting.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, limitedUnknown.StatusCode);

        // Після вікна (30 с + запас) ліміт відновлюється.
        await Task.Delay(TimeSpan.FromSeconds(31));
        using var recovered = await client.PostAsJsonAsync("/api/auth/login", wrong);
        Assert.Equal(HttpStatusCode.Unauthorized, recovered.StatusCode);
    }

    private static async Task<string> StableShapeAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        if (string.IsNullOrWhiteSpace(body)) return "";
        using var doc = JsonDocument.Parse(body);
        var parts = new[] { "type", "title", "status", "detail" }
            .Select(name => doc.RootElement.TryGetProperty(name, out var value) ? $"{name}={value}" : $"{name}=-");
        return string.Join("|", parts);
    }
}

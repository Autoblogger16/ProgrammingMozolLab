using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// ЛР 6, етап 1, п. 4: очікувані помилки в Production лишаються коректними 4xx.
// Через SecurePolicy.Always cookie у Production не повертається по http://localhost,
// тому перевірка йде в окремому Production test host (TestServer, https BaseAddress).
// Це доказ поведінки застосунку, а не TLS чи HSTS. БД перед тестом скидається в Development.
public sealed class ProductionProfileTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string Password =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task Production_ExpectedErrors_Keep4xxSemantics()
    {
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("ConnectionStrings:SecureLab",
                "Host=127.0.0.1;Port=54329;Database=securelab;Username=securelab;"
                + "Password=local-study-password;Include Error Detail=false");
        });

        // Передумова: тестовий host справді працює в Production.
        Assert.Equal("Production",
            production.Services.GetRequiredService<IHostEnvironment>().EnvironmentName);

        // Анонімний запит до захищеного маршруту: 401 без redirect.
        using var anonymous = production.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using var anonymousResponse = await anonymous.GetAsync("/api/auth/session-check");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousResponse.StatusCode);

        // Вхід через цей самий Production host і дозволений GET.
        using var alice = await production.LoginAsync("alice", Password);
        using var allowed = await alice.GetAsync("/api/auth/session-check");
        Assert.Equal(HttpStatusCode.NoContent, allowed.StatusCode);

        // Некоректний фільтр: 400 Validation Problem Details.
        using var badFilter = await alice.GetAsync("/api/incidents?status=Unknown");
        Assert.Equal(HttpStatusCode.BadRequest, badFilter.StatusCode);
        Assert.Equal("application/problem+json", badFilter.Content.Headers.ContentType?.MediaType);

        // Неіснуючий інцидент: 404 Problem Details.
        using var missing = await alice.GetAsync("/api/incidents/99999999-9999-9999-9999-999999999999");
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        Assert.Equal("application/problem+json", missing.Content.Headers.ContentType?.MediaType);

        // Чужий інцидент: 404, як у ЛР 4.
        using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);

        // Triage від Reporter: з валідним токеном доходить до перевірки ролі й отримує 403.
        await alice.UseAntiforgeryTokenAsync();
        using var triage = await alice.PostAsync($"/api/incidents/{DbSeeder.AliceIncidentId}/triage", content: null);
        Assert.Equal(HttpStatusCode.Forbidden, triage.StatusCode);
    }

    [Fact]
    public async Task UnexpectedError_KeepsSecurityHeaders()
    {
        // F-01: недосяжна БД → 500 через UseExceptionHandler.
        using var broken = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("ConnectionStrings:SecureLab",
                "Host=127.0.0.1;Port=54399;Database=securelab;Username=securelab;"
                + "Password=unreachable-study-value;Include Error Detail=false");
        });
        using var client = broken.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "NotARealPassword1!" });

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Contains("frame-ancestors 'none'",
            response.Headers.GetValues("Content-Security-Policy").Single());
    }
}
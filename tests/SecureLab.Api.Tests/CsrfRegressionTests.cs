using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// ЛР 6: REG-CSRF-01 на POST /api/incidents і REG-CSRF-02 для решти cookie-периметра.
// Кожна відмова перевіряється не лише за статусом, а й повторним читанням стану.
public sealed class CsrfRegressionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string Password =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static object NewIncident(string title) => new
    {
        title,
        description = "REG-CSRF-01",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
    };

    private static async Task<bool> ListContainsAsync(HttpClient client, string title) =>
        (await client.GetStringAsync("/api/incidents")).Contains(title);

    // REG-CSRF-01: без токена і з невалідним токеном — 400 і інцидент не створено;
    // з валідною парою — 201 і інцидент з'являється у списку.
    [Fact]
    public async Task RegCsrf01_CreateWithoutOrInvalidToken_Rejected_ThenValidPairSucceeds()
    {
        using var alice = await factory.LoginAsync("alice", Password);
        var title = $"CSRF-{Guid.NewGuid():N}"[..20];

        // Лише cookie сеансу, без request token.
        using var noToken = await alice.PostAsJsonAsync("/api/incidents", NewIncident(title));
        Assert.Equal(HttpStatusCode.BadRequest, noToken.StatusCode);
        Assert.Equal("application/problem+json", noToken.Content.Headers.ContentType?.MediaType);
        Assert.False(await ListContainsAsync(alice, title));

        // Вигаданий токен у правильному заголовку.
        using var invalid = new HttpRequestMessage(HttpMethod.Post, "/api/incidents")
        {
            Content = JsonContent.Create(NewIncident(title))
        };
        invalid.Headers.Add(AntiforgeryTestExtensions.HeaderName, "not-a-valid-token");
        using var invalidResponse = await alice.SendAsync(invalid);
        Assert.Equal(HttpStatusCode.BadRequest, invalidResponse.StatusCode);
        Assert.False(await ListContainsAsync(alice, title));

        // Легітимний сценарій: токен отримано тим самим клієнтом.
        await alice.UseAntiforgeryTokenAsync();
        using var accepted = await alice.PostAsJsonAsync("/api/incidents", NewIncident(title));
        Assert.Equal(HttpStatusCode.Created, accepted.StatusCode);
        Assert.True(await ListContainsAsync(alice, title));
    }

    // Токен прив'язано до principal: токен Alice не підходить для сеансу Bob.
    [Fact]
    public async Task TokenOfAlice_IsRejectedForBob()
    {
        using var alice = await factory.LoginAsync("alice", Password);
        await alice.UseAntiforgeryTokenAsync();
        var aliceToken = alice.DefaultRequestHeaders
            .GetValues(AntiforgeryTestExtensions.HeaderName).Single();

        using var bob = await factory.LoginAsync("bob", Password);
        var title = $"CSRF-B-{Guid.NewGuid():N}"[..20];
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/incidents")
        {
            Content = JsonContent.Create(NewIncident(title))
        };
        request.Headers.Add(AntiforgeryTestExtensions.HeaderName, aliceToken);
        using var response = await bob.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(await ListContainsAsync(bob, title));
    }

    // REG-CSRF-02: SC-02–SC-05 без токена — той самий 400, ресурс і сеанс не змінено.
    [Fact]
    public async Task Perimeter_WithoutToken_Returns400_AndStateUnchanged()
    {
        using var alice = await factory.LoginAsync("alice", Password);
        var id = DbSeeder.AliceIncidentId;
        var before = await alice.GetStringAsync($"/api/incidents/{id}");

        // SC-02 PUT
        using var put = await alice.PutAsJsonAsync($"/api/incidents/{id}", new
        {
            title = "CSRF changed",
            description = "CSRF changed"
        });
        Assert.Equal(HttpStatusCode.BadRequest, put.StatusCode);

        // SC-03 DELETE
        using var delete = await alice.DeleteAsync($"/api/incidents/{id}");
        Assert.Equal(HttpStatusCode.BadRequest, delete.StatusCode);

        // SC-04 triage від Analyst
        using var morgan = await factory.LoginAsync("morgan", Password);
        using var triage = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
        Assert.Equal(HttpStatusCode.BadRequest, triage.StatusCode);

        // Інцидент не змінено: назва, опис і статус ті самі.
        var after = await alice.GetStringAsync($"/api/incidents/{id}");
        Assert.Equal(before, after);

        // SC-05 logout без токена: 400, а сеанс лишається активним.
        using var logout = await alice.PostAsync("/api/auth/logout", content: null);
        Assert.Equal(HttpStatusCode.BadRequest, logout.StatusCode);
        using var me = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
    }
}

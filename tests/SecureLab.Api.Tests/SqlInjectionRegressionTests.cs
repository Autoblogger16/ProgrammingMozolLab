using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace SecureLab.Api.Tests;

// ЛР 6: S-02 з ЛР 2 — тепер автоматично, а не лише вручну.
public sealed class SqlInjectionRegressionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task S02_SqlPayload_IsTreatedAsText_AndSortByIsAllowlisted()
    {
        // Окремий host — окремий лічильник rate limit для пошуку.
        using var host = factory.WithWebHostBuilder(_ => { });
        using var client = host.CreateClient();

        // Контроль: порожній пошук повертає seed-інциденти.
        var all = await client.GetFromJsonAsync<List<JsonElement>>("/api/incidents/search?q=");
        Assert.NotNull(all);
        Assert.NotEmpty(all);

        // Класичний payload не розширює вибірку: його шукають як звичайний текст.
        var payload = Uri.EscapeDataString("' OR '1'='1");
        var injected = await client.GetFromJsonAsync<List<JsonElement>>($"/api/incidents/search?q={payload}");
        Assert.NotNull(injected);
        Assert.Empty(injected);

        // Довільний sortBy із SQL не потрапляє в ORDER BY — лише 400 від allowlist.
        var sort = Uri.EscapeDataString("title; DROP TABLE incidents");
        using var badSort = await client.GetAsync($"/api/incidents/search?sortBy={sort}");
        Assert.Equal(HttpStatusCode.BadRequest, badSort.StatusCode);
    }
}

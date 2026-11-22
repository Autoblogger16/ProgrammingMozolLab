using System.Net;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// ЛР 6: перевірка політики rate limiting "search" на кількох partitions.
public sealed class SearchRateLimitTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string Password =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private const string SearchUrl = "/api/incidents/search?q=навчальн";

    [Fact]
    public async Task Search_QuotaPerUser_Returns429_OtherUserNotBlocked_ThenRecovers()
    {
        // Окремий host має власний лічильник, тож інші тести на результат не впливають.
        using var host = factory.WithWebHostBuilder(_ => { });
        using var alice = await host.LoginAsync("alice", Password);
        using var bob = await host.LoginAsync("bob", Password);

        // 1. У межах квоти пошук працює як звичайно.
        for (var i = 0; i < 5; i++)
        {
            using var ok = await alice.GetAsync(SearchUrl);
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        // 2. Шостий запит alice вичерпує квоту і отримує 429.
        using var limited = await alice.GetAsync(SearchUrl);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);

        // 3. Інший користувач має власний лічильник і не блокується.
        using var bobSearch = await bob.GetAsync(SearchUrl);
        Assert.Equal(HttpStatusCode.OK, bobSearch.StatusCode);

        // 4. Ліміт пошуку не змінює авторизацію: інші маршрути alice працюють, як і раніше.
        using var own = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.OK, own.StatusCode);
        using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);

        // 5. Після завершення вікна (10 с + запас) пошук alice знову доступний.
        await Task.Delay(TimeSpan.FromSeconds(11));
        using var recovered = await alice.GetAsync(SearchUrl);
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
    }
}

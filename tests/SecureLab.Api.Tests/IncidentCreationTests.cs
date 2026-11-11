using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class IncidentCreationTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task T02_ValidationFails_Returns400()
    {
        var request = new
        {
            title = "Check T-02",
            description = "Перевірка валідації",
            severity = "InvalidSeverity123",
            occurredAtUtc = DateTimeOffset.UtcNow.AddDays(5)
        };

        using var response = await _client.PostAsJsonAsync("/api/incidents", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var errors = document.RootElement.GetProperty("errors");
        Assert.True(errors.TryGetProperty("severity", out _));
        Assert.True(errors.TryGetProperty("occurredAtUtc", out _));
        Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task T03_DuplicateTitle_Returns409()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        var request = new
        {
            title,
            description = "Цей опис є достатньо довгим (більше 40 символів), щоб пройти cross-field перевірку.",
            severity = "Critical",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-2)
        };

        try
        {
            using var first = await _client.PostAsJsonAsync("/api/incidents", request);
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            using var second = await _client.PostAsJsonAsync("/api/incidents", request);
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
            Assert.Equal("application/problem+json", second.Content.Headers.ContentType?.MediaType);
        }
        finally
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
        }
    }
}

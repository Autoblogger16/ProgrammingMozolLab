using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SecureLab.Api.Tests;

public class IncidentCreationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public IncidentCreationTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task T02_ValidationFails_Returns400()
    {
        var request = new
        {
            Title = "Check T-02",
            Description = "Перевірка валідації",
            Severity = "InvalidSeverity123",
            OccurredAtUtc = DateTimeOffset.UtcNow.AddDays(5)
        };

        var response = await _client.PostAsJsonAsync("/api/incidents", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task T03_DuplicateTitle_Returns409()
    {
        var title = $"Regression-{Guid.NewGuid():N}";

        var request = new
        {
            Title = title,
            Description = "Цей опис є достатньо довгим (більше 40 символів), щоб пройти cross-field перевірку.",
            Severity = "Critical",
            OccurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-2)
        };

        var response1 = await _client.PostAsJsonAsync("/api/incidents", request);

        Assert.Equal(HttpStatusCode.Created, response1.StatusCode);

        var response2 = await _client.PostAsJsonAsync("/api/incidents", request);

        Assert.Equal(HttpStatusCode.Conflict, response2.StatusCode);
    }
}
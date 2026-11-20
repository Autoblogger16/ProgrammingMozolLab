using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// ЛР 4: authorization test matrix (A-01 ... A-12) через HTTP boundary.
// Один користувач - один HttpClient зі своїм cookie. Пароль - лише зі змінної середовища.
public sealed class AuthorizationTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static readonly Guid AlicePublicCommentId = Guid.Parse("30000000-0000-0000-0000-000000000001");
    private static readonly Guid BobCommentId = Guid.Parse("30000000-0000-0000-0000-000000000002");
    private static readonly Guid InternalCommentId = Guid.Parse("30000000-0000-0000-0000-000000000003");

    // Rate limiter дозволяє лише 10 login за 30 с з однієї адреси, тому кожен користувач
    // входить один раз на весь клас, а клієнти перевикористовуються між тестами.
    private static readonly Dictionary<string, HttpClient> Clients = new();

    private async Task<HttpClient> UserAsync(string userName)
    {
        if (!Clients.TryGetValue(userName, out var client))
        {
            client = await factory.LoginAsync(userName, Password);
            Clients[userName] = client;
        }
        return client;
    }

    private static string Password =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // ---------- A-01: анонім ----------
    [Fact]
    public async Task A01_Details_AsAnonymous_Returns401_WithoutRedirect()
    {
        using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using var response = await anonymous.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.DoesNotContain("Невідома спроба входу", await response.Content.ReadAsStringAsync());
    }

    // ---------- A-02 / A-03 / A-03R: details ----------
    [Fact]
    public async Task A02_Details_AsOwner_ReturnsOwnIncident()
    {
        var alice = await UserAsync("alice");

        var incident = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(DbSeeder.AliceIncidentId.ToString(), incident!["id"]!.GetValue<string>());
        Assert.Equal("Аліса Коваль", incident["ownerDisplayName"]!.GetValue<string>());
    }

    [Fact]
    public async Task A03_Details_AsNonOwner_ReturnsNotFound_WithoutBobData()
    {
        var alice = await UserAsync("alice");

        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.DoesNotContain("Боб Мельник", body);
        Assert.DoesNotContain("Невідома спроба входу", body);
    }

    [Fact]
    public async Task A03R_Details_AsAnalyst_ReturnsForeignIncident()
    {
        var morgan = await UserAsync("morgan");

        using var response = await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ---------- A-04: чужий update / delete без зміни стану ----------
    [Fact]
    public async Task A04_Update_AsNonOwner_ReturnsNotFound_AndDoesNotChangeIncident()
    {
        var alice = await UserAsync("alice");
        var bob = await UserAsync("bob");
        var before = await bob.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.BobIncidentId}");

        using var response = await alice.PutAsJsonAsync($"/api/incidents/{DbSeeder.BobIncidentId}",
            new { title = "Змінено Alice", description = "Спроба змінити чужий інцидент у тесті." });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        // Стан читає власник Bob, бо Alice цього ресурсу не бачить.
        var after = await bob.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.Equal(before!["title"]!.GetValue<string>(), after!["title"]!.GetValue<string>());
        Assert.Equal(before["description"]!.GetValue<string>(), after["description"]!.GetValue<string>());
    }

    [Fact]
    public async Task A04_Delete_AsNonOwner_ReturnsNotFound_AndIncidentStillExists()
    {
        var alice = await UserAsync("alice");
        var bob = await UserAsync("bob");

        using var response = await alice.DeleteAsync($"/api/incidents/{DbSeeder.BobIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        using var check = await bob.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.Equal(HttpStatusCode.OK, check.StatusCode);
    }

    // ---------- A-05: list лише дозволеної множини ----------
    [Fact]
    public async Task A05_List_AsAlice_ReturnsOnlyOwnIncidents()
    {
        var alice = await UserAsync("alice");

        var incidents = await alice.GetFromJsonAsync<List<JsonObject>>("/api/incidents");
        var ids = incidents!.Select(item => item["id"]!.GetValue<string>()).ToList();

        Assert.Contains(DbSeeder.AliceIncidentId.ToString(), ids);
        Assert.DoesNotContain(DbSeeder.BobIncidentId.ToString(), ids);
        Assert.DoesNotContain("20000000-0000-0000-0000-000000000004", ids);
    }

    // ---------- A-06 / A-07: privileged transition ----------
    [Fact]
    public async Task A06_Triage_AsReporter_ReturnsForbidden_AndStatusUnchanged()
    {
        var alice = await UserAsync("alice");
        var id = await CreateIncidentAsync(alice);
        try
        {
            using var response = await alice.PostAsJsonAsync($"/api/incidents/{id}/triage",
                new { status = "Closed", role = "Analyst", isTransitionAllowed = true });

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            var after = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{id}");
            Assert.Equal("New", after!["status"]!.GetValue<string>());
        }
        finally
        {
            await RemoveIncidentAsync(id);
        }
    }

    [Fact]
    public async Task A07_Triage_AsAnalyst_MovesNewToTriaged_ThenReturnsConflict()
    {
        var alice = await UserAsync("alice");
        var morgan = await UserAsync("morgan");
        var id = await CreateIncidentAsync(alice);
        try
        {
            using var first = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
            Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);

            var after = await morgan.GetFromJsonAsync<JsonObject>($"/api/incidents/{id}");
            Assert.Equal("Triaged", after!["status"]!.GetValue<string>());

            using var second = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        }
        finally
        {
            await RemoveIncidentAsync(id);
        }
    }

    // ---------- A-08a: forged owner/role/status ігноруються ----------
    [Fact]
    public async Task A08a_Update_WithForgedOwnerRoleStatus_ChangesOnlyContent()
    {
        var alice = await UserAsync("alice");
        var id = await CreateIncidentAsync(alice);
        try
        {
            using var response = await alice.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = $"ЛР4 оновлено {Guid.NewGuid():N}",
                description = "Власник оновив опис інциденту в тесті.",
                ownerUserId = DbSeeder.BobId,
                role = "Analyst",
                status = "Closed",
                severity = "Critical"
            });

            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            var after = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{id}");
            Assert.StartsWith("ЛР4 оновлено", after!["title"]!.GetValue<string>());
            Assert.Equal("Аліса Коваль", after["ownerDisplayName"]!.GetValue<string>());
            Assert.Equal("New", after["status"]!.GetValue<string>());
            Assert.Equal("Low", after["severity"]!.GetValue<string>());
        }
        finally
        {
            await RemoveIncidentAsync(id);
        }
    }

    // ---------- A-10: чужий = неіснуючий ----------
    [Fact]
    public async Task A10_Details_ForeignAndUnknown_ReturnSameProblemDetails()
    {
        var alice = await UserAsync("alice");

        using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var unknown = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(unknown.StatusCode, foreign.StatusCode);
        Assert.Equal(unknown.Content.Headers.ContentType?.ToString(), foreign.Content.Headers.ContentType?.ToString());

        var foreignBody = await foreign.Content.ReadFromJsonAsync<JsonObject>();
        var unknownBody = await unknown.Content.ReadFromJsonAsync<JsonObject>();
        foreignBody!.Remove("traceId");   // єдина дозволена відмінність
        unknownBody!.Remove("traceId");
        Assert.True(JsonNode.DeepEquals(unknownBody, foreignBody));
        Assert.DoesNotContain(DbSeeder.BobIncidentId.ToString(), foreignBody.ToJsonString());
    }

    // ---------- A-12: дочірній ресурс і internal comment ----------
    [Fact]
    public async Task A12_Comment_AsReporter_ForeignOrInternal_ReturnsNotFound()
    {
        var alice = await UserAsync("alice");

        using var own = await alice.GetAsync($"/api/incident-comments/{AlicePublicCommentId}");
        using var foreign = await alice.GetAsync($"/api/incident-comments/{BobCommentId}");
        using var internalComment = await alice.GetAsync($"/api/incident-comments/{InternalCommentId}");

        Assert.Equal(HttpStatusCode.OK, own.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, internalComment.StatusCode);
        Assert.DoesNotContain("Розпочато перевірку", await foreign.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A12_InternalComment_VisibleOnlyToAnalyst()
    {
        var alice = await UserAsync("alice");
        var morgan = await UserAsync("morgan");

        var forAlice = await alice.GetStringAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        var forMorgan = await morgan.GetStringAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        using var direct = await morgan.GetAsync($"/api/incident-comments/{InternalCommentId}");

        Assert.DoesNotContain(InternalCommentId.ToString(), forAlice);
        Assert.Contains(InternalCommentId.ToString(), forMorgan);
        Assert.Equal(HttpStatusCode.OK, direct.StatusCode);
    }

    // ---------- helpers ----------
    // Позитивні mutation-тести працюють із власним новим інцидентом (статус New), а не з seed.
    private static async Task<Guid> CreateIncidentAsync(HttpClient owner)
    {
        using var response = await owner.PostAsJsonAsync("/api/incidents", new
        {
            title = $"ЛР4 тест {Guid.NewGuid():N}",
            description = "Тестовий інцидент для перевірки авторизації.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        return Guid.Parse(body!["id"]!.GetValue<string>());
    }

    // Прибираємо лише власний тестовий запис і його дочірні рядки.
    private async Task RemoveIncidentAsync(Guid id)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.IncidentStatusHistory.Where(item => item.IncidentId == id).ExecuteDeleteAsync();
        await db.IncidentComments.Where(item => item.IncidentId == id).ExecuteDeleteAsync();
        await db.Incidents.Where(item => item.Id == id).ExecuteDeleteAsync();
    }
}

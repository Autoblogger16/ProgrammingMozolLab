using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

// ЛР 6: REG-AUDIT-01 — audit trail привілейованого переходу Incident.Status (triage).
public sealed class AuditTrailTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string Password =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Новий інцидент зі статусом New, щоб не змінювати seed-дані.
    private static async Task<Guid> CreateIncidentAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"AUDIT-{Guid.NewGuid():N}",
            description = "REG-AUDIT-01",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        });
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("id").GetGuid();
    }

    // Читаємо історію статусів прямо з БД, а не з відповіді API.
    private async Task<List<IncidentStatusHistory>> HistoryAsync(Guid incidentId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.IncidentStatusHistory.AsNoTracking()
            .Where(item => item.IncidentId == incidentId)
            .ToListAsync();
    }

    // Прибираємо лише власний тестовий інцидент і його історію.
    private async Task RemoveIncidentAsync(Guid id)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.IncidentStatusHistory.Where(item => item.IncidentId == id).ExecuteDeleteAsync();
        await db.Incidents.Where(item => item.Id == id).ExecuteDeleteAsync();
    }

    [Fact]
    public async Task Triage_DeniedReporter_NoChange_AllowedAnalyst_WritesAuditRecord()
    {
        using var alice = await factory.LoginAsync("alice", Password);
        await alice.UseAntiforgeryTokenAsync();
        var id = await CreateIncidentAsync(alice);
        try
        {
            // 1. Відмова Reporter: 403, статус лишається New, у історії жодного запису.
            using var denied = await alice.PostAsync($"/api/incidents/{id}/triage", content: null);
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            var afterDenied = await alice.GetFromJsonAsync<JsonElement>($"/api/incidents/{id}");
            Assert.Equal("New", afterDenied.GetProperty("status").GetString());
            Assert.Empty(await HistoryAsync(id));

            // 2. Дозволений перехід Analyst: 204, статус стає Triaged.
            using var morgan = await factory.LoginAsync("morgan", Password);
            await morgan.UseAntiforgeryTokenAsync();
            var before = DateTimeOffset.UtcNow;
            using var allowed = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
            Assert.Equal(HttpStatusCode.NoContent, allowed.StatusCode);

            // 3. Рівно один запис аудиту: хто, яка дія, над чим, результат і коли.
            var record = Assert.Single(await HistoryAsync(id));
            Assert.Equal(DbSeeder.MorganId, record.ChangedByUserId);        // хто
            Assert.Equal("Triage виконано аналітиком.", record.Note);       // яка дія
            Assert.Equal(id, record.IncidentId);                            // над яким ресурсом
            Assert.Equal(IncidentStatus.New, record.OldStatus);             // результат: New -> Triaged
            Assert.Equal(IncidentStatus.Triaged, record.NewStatus);
            Assert.True(record.CreatedAtUtc >= before.AddSeconds(-5));      // коли
        }
        finally
        {
            await RemoveIncidentAsync(id);
        }
    }
}

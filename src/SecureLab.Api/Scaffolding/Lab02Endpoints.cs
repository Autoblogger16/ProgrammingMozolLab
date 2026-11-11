using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        // ==========================================
        // ПОШУК: LINQ + EF.Functions.ILike, allowlist для sortBy
        // ==========================================
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            // Значення користувача лише екрануємо для LIKE;
            // EF Core передає pattern у PostgreSQL окремим параметром.
            var pattern = "%" + EscapeLike(q ?? "") + "%";

            var found = db.Incidents.AsNoTracking()
                .Where(item => EF.Functions.ILike(item.Title, pattern, "\\")
                            || EF.Functions.ILike(item.Description, pattern, "\\"));

            // Allowlist: клієнт лише обирає одну з написаних сервером гілок.
            IQueryable<Incident>? ordered = sortBy switch
            {
                null or "" or "createdAtUtc" => found
                    .OrderByDescending(item => item.CreatedAtUtc)
                    .ThenBy(item => item.Id),

                "severity" => found
                    .OrderBy(item =>
                        item.Severity == IncidentSeverity.Critical ? 0 :
                        item.Severity == IncidentSeverity.High ? 1 :
                        item.Severity == IncidentSeverity.Medium ? 2 : 3)
                    .ThenBy(item => item.Id),

                "status" => found
                    .OrderBy(item =>
                        item.Status == IncidentStatus.New ? 0 :
                        item.Status == IncidentStatus.Triaged ? 1 :
                        item.Status == IncidentStatus.InProgress ? 2 :
                        item.Status == IncidentStatus.Resolved ? 3 : 4)
                    .ThenBy(item => item.Id),

                _ => null
            };

            if (ordered is null)
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."]
                });
            }

            var rows = await ordered.Take(50).ToListAsync(ct);

            var items = rows.Select(row => new IncidentSearchItemResponse(
                row.Id,
                row.Title,
                row.Description,
                row.Severity.ToString(),
                row.Status.ToString(),
                row.CreatedAtUtc));

            return Results.Ok(items);
        });

        // ==========================================
        // СТВОРЕННЯ ІНЦИДЕНТУ: POST /api/incidents
        // ==========================================
        app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, CancellationToken ct) =>
        {
            var now = DateTimeOffset.UtcNow; // фіксуємо один раз
            var errors = new Dictionary<string, string[]>();

            // 1. Required (після Trim) і довжина (до Trim).
            if (string.IsNullOrWhiteSpace(request.Title))
                errors["title"] = ["Заголовок обов'язковий."];
            else if (request.Title.Length > 160)
                errors["title"] = ["Заголовок не може бути довшим за 160 символів."];

            if (string.IsNullOrWhiteSpace(request.Description))
                errors["description"] = ["Опис обов'язковий."];
            else if (request.Description.Length > 4000)
                errors["description"] = ["Опис не може бути довшим за 4000 символів."];

            // 2. Enum: і перетворення, і належність до оголошених значень ("7" відхиляється).
            var severityIsValid =
                Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
                && Enum.IsDefined(severity);
            if (!severityIsValid)
                errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];

            // 3. Дата: обов'язкова і не пізніше now + 5 хвилин.
            if (request.OccurredAtUtc is null)
                errors["occurredAtUtc"] = ["Час виникнення обов'язковий."];
            else if (request.OccurredAtUtc > now.AddMinutes(5))
                errors["occurredAtUtc"] = ["Час виникнення не може випереджати поточний час більш ніж на 5 хвилин."];

            // 4. Нормалізація по одному разу.
            var title = request.Title?.Trim() ?? "";
            var description = request.Description?.Trim() ?? "";

            // 5. Cross-field (T-09): High/Critical => description після Trim() >= 40 символів.
            if (severityIsValid
                && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical)
                && !errors.ContainsKey("description")
                && description.Length < 40)
            {
                errors["description"] = ["Для High або Critical опис має містити щонайменше 40 символів."];
            }

            // 6. Усі помилки контракту — одна відповідь 400 до звернення до БД.
            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            // 7. Предметний конфлікт (T-03): той самий title (з урахуванням регістру)
            //    серед інцидентів у статусах New, Triaged, InProgress, Resolved.
            var duplicateExists = await db.Incidents.AnyAsync(item =>
                item.Title == title
                && (item.Status == IncidentStatus.New
                    || item.Status == IncidentStatus.Triaged
                    || item.Status == IncidentStatus.InProgress
                    || item.Status == IncidentStatus.Resolved), ct);

            if (duplicateExists)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Конфлікт заголовка",
                    detail: "Не закритий інцидент з таким заголовком уже існує.");
            }

            // 8. Entity: server-managed поля встановлює лише сервер.
            var incident = new Incident
            {
                Id = Guid.NewGuid(),
                OwnerUserId = DbSeeder.AliceId,
                Title = title,
                Description = description,
                Severity = severity,
                Status = IncidentStatus.New,
                OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime(),
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };
            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);

            // 9. Response DTO: лише поля зовнішнього контракту.
            var response = new CreatedIncidentResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.UpdatedAtUtc);

            return Results.Created($"/api/incidents/{incident.Id}", response);
        });
    }

    // Екранування для literal substring: спершу \, потім % і _.
    private static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\")
             .Replace("%", "\\%")
             .Replace("_", "\\_");
}

// Request DTO: лише поля, які може надсилати клієнт.
public sealed record CreateIncidentRequest(
    string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);

// Response DTO для 201 Created.
public sealed record CreatedIncidentResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

// Елемент відповіді пошуку (іменований тип для тестів: List<IncidentSearchItemResponse>).
public sealed record IncidentSearchItemResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset CreatedAtUtc);

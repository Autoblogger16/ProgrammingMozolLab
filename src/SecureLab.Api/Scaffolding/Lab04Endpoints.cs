using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

// ЛР 4. Нові маршрути для Incident: update вмісту і привілейований перехід triage.
public static class Lab04Endpoints
{
    public static void MapLab04Endpoints(this WebApplication app)
    {
        // ЛР 4 (vulnerable PoC): інцидент шукається лише за id,
        // власник не порівнюється з principal.
        app.MapPut("/api/incidents/{id:guid}", async (
            Guid id, UpdateIncidentRequest request, SecureLabDbContext db, CancellationToken ct) =>
        {
            var errors = ValidateUpdate(request);
            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, ct);
            if (incident is null)
                return IncidentNotFound();

            incident.Title = request.Title!.Trim();
            incident.Description = request.Description!.Trim();
            incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization();

        // ЛР 4 (vulnerable PoC): привілейований перехід New -> Triaged
        // без перевірки ролі Analyst.
        app.MapPost("/api/incidents/{id:guid}/triage", async (
            Guid id, SecureLabDbContext db, CancellationToken ct) =>
        {
            var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, ct);
            if (incident is null)
                return IncidentNotFound();

            if (incident.Status != IncidentStatus.New)
            {
                return Results.Problem(
                    title: "Недопустимий перехід статусу",
                    detail: "Triage можливий лише для інциденту зі статусом New.",
                    statusCode: StatusCodes.Status409Conflict);
            }

            incident.Status = IncidentStatus.Triaged;
            incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization();
    }

    // Перевірка вмісту update: ті самі межі, що й під час створення.
    private static Dictionary<string, string[]> ValidateUpdate(UpdateIncidentRequest request)
    {
        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrWhiteSpace(request.Title))
            errors["title"] = ["Заголовок обов'язковий."];
        else if (request.Title.Length > 160)
            errors["title"] = ["Заголовок не може бути довшим за 160 символів."];

        if (string.IsNullOrWhiteSpace(request.Description))
            errors["description"] = ["Опис обов'язковий."];
        else if (request.Description.Length > 4000)
            errors["description"] = ["Опис не може бути довшим за 4000 символів."];

        return errors;
    }

    // Одна відповідь 404 без id у тексті: однакова для чужого й неіснуючого ресурсу.
    private static IResult IncidentNotFound() =>
        Results.Problem(title: "Інцидент не знайдено", statusCode: StatusCodes.Status404NotFound);
}

// Request DTO для update: лише content fields. Owner, status, severity і role сюди не входять.
public sealed record UpdateIncidentRequest(string? Title, string? Description);
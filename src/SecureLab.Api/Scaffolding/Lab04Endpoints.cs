using SecureLab.Api.Security;
using System.Diagnostics;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Scaffolding;

// ЛР 4 (fixed). Маршрути Incident: update, delete, triage і дочірній ресурс коментаря.
// Кожне рішення: principal (id + роль) + завантажений ресурс + операція.
public static class Lab04Endpoints
{
    public static void MapLab04Endpoints(this WebApplication app)
    {

        app.MapPut("/api/incidents/{id:guid}", async (
            Guid id, UpdateIncidentRequest request, ClaimsPrincipal user, HttpContext http,
            SecureLabDbContext db, ILoggerFactory loggers, CancellationToken ct) =>
        {
            var errors = ValidateUpdate(request);
            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            // Без AsNoTracking: EF має відстежувати entity, щоб зберегти зміни.
            var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, ct);
            var userId = IncidentAccess.CurrentUserId(user);
            var isAnalyst = IncidentAccess.IsAnalyst(user);

            // 1. Ресурс не видно суб'єкту -> такий самий 404, як для неіснуючого.
            if (incident is null || !IncidentAccess.CanView(incident, userId, isAnalyst))
                return IncidentAccess.NotFound();

            // 2. Ресурс видно (Analyst), але редагувати може лише власник -> 403.
            if (incident.OwnerUserId != userId)
                return IncidentAccess.Forbidden(loggers, http, userId, "incident.update", id);

            // 3. Зміна стану - лише після обох перевірок.
            incident.Title = request.Title!.Trim();
            incident.Description = request.Description!.Trim();
            incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization().AddEndpointFilter<AntiforgeryFilter>();


        app.MapDelete("/api/incidents/{id:guid}", async (
            Guid id, ClaimsPrincipal user, HttpContext http,
            SecureLabDbContext db, ILoggerFactory loggers, CancellationToken ct) =>
        {
            var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, ct);
            var userId = IncidentAccess.CurrentUserId(user);
            var isAnalyst = IncidentAccess.IsAnalyst(user);

            if (incident is null || !IncidentAccess.CanView(incident, userId, isAnalyst))
                return IncidentAccess.NotFound();

            if (incident.OwnerUserId != userId)
                return IncidentAccess.Forbidden(loggers, http, userId, "incident.delete", id);

            // Власник знає про ресурс, але після початку обробки видаляти не можна.
            if (incident.Status != IncidentStatus.New)
                return IncidentAccess.Forbidden(loggers, http, userId, "incident.delete", id);

            db.Incidents.Remove(incident);
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        }).RequireAuthorization().AddEndpointFilter<AntiforgeryFilter>();


        app.MapPost("/api/incidents/{id:guid}/triage", async (
            Guid id, ClaimsPrincipal user, HttpContext http,
            SecureLabDbContext db, ILoggerFactory loggers, CancellationToken ct) =>
        {
            var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, ct);
            var userId = IncidentAccess.CurrentUserId(user);
            var isAnalyst = IncidentAccess.IsAnalyst(user);

            // Чужий інцидент Reporter не бачить -> 404, як і неіснуючий.
            if (incident is null || !IncidentAccess.CanView(incident, userId, isAnalyst))
                return IncidentAccess.NotFound();

            // Свій інцидент видно, але роль не дозволяє дію -> 403 + audit event.
            if (!isAnalyst)
                return IncidentAccess.Forbidden(loggers, http, userId, "incident.triage", id);

            // Допустимий лише перехід із New; новий стан задає сервер, не клієнт.
            if (incident.Status != IncidentStatus.New)
            {
                return Results.Problem(
                    title: "Недопустимий перехід статусу",
                    detail: "Triage можливий лише для інциденту зі статусом New.",
                    statusCode: StatusCodes.Status409Conflict);
            }

            var now = DateTimeOffset.UtcNow;
            db.IncidentStatusHistory.Add(new IncidentStatusHistory
            {
                Id = Guid.NewGuid(),
                IncidentId = incident.Id,
                ChangedByUserId = userId,
                OldStatus = incident.Status,
                NewStatus = IncidentStatus.Triaged,
                Note = "Triage виконано аналітиком.",
                CreatedAtUtc = now
            });
            var oldStatus = incident.Status;
            incident.Status = IncidentStatus.Triaged;
            incident.UpdatedAtUtc = now;
            await db.SaveChangesAsync(ct);

            // ЛР 6: audit trail дозволеного привілейованого переходу. Окрім рядка в
            // incident_status_history, у журнал іде подія incident.status_changed —
            // лише ідентифікатори, дія, результат, статуси, час і trace; без тіла запиту, cookie й токенів.
            loggers.CreateLogger("SecureLab.Audit").LogInformation(
                "Audit {EventType}: user {UserId}, action {Action}, incident {IncidentId}, result {Result}, {OldStatus} -> {NewStatus}, at {OccurredAtUtc}, trace {TraceId}",
                "incident.status_changed", userId, "incident.triage", incident.Id, "allowed",
                oldStatus, incident.Status, now, Activity.Current?.Id ?? http.TraceIdentifier);

            return Results.NoContent();
        }).RequireAuthorization().AddEndpointFilter<AntiforgeryFilter>();


        app.MapGet("/api/incident-comments/{id:guid}", async (
            Guid id, ClaimsPrincipal user, SecureLabDbContext db, CancellationToken ct) =>
        {
            var userId = IncidentAccess.CurrentUserId(user);
            var isAnalyst = IncidentAccess.IsAnalyst(user);

            // Умова доступу до parent стоїть у тому самому запиті, що й пошук коментаря.
            var comment = await db.IncidentComments
                .AsNoTracking()
                .Where(item => item.Id == id
                    && (isAnalyst || (item.Incident.OwnerUserId == userId && !item.IsInternal)))
                .Select(item => new IncidentCommentResponse(
                    item.Id,
                    item.Author.DisplayName,
                    item.Text,
                    item.CreatedAtUtc))
                .SingleOrDefaultAsync(ct);

            return comment is null
                ? Results.Problem(title: "Коментар не знайдено", statusCode: StatusCodes.Status404NotFound)
                : Results.Ok(comment);
        }).RequireAuthorization();
    }


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
}

// ЛР 4: централізоване рішення доступу до Incident - одне місце для всіх маршрутів.
public static class IncidentAccess
{
    // id і роль беруться лише з principal (cookie), не з URL чи body.
    public static Guid CurrentUserId(ClaimsPrincipal user) =>
        Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);

    public static bool IsAnalyst(ClaimsPrincipal user) =>
        user.IsInRole(DbSeeder.AnalystRole);

    // Видимість за матрицею: Analyst бачить усі, Reporter/Admin - лише свої.
    public static bool CanView(Incident incident, Guid userId, bool isAnalyst) =>
        isAnalyst || incident.OwnerUserId == userId;

    // Одна відповідь 404 без id: однакова для чужого й неіснуючого ресурсу.
    public static IResult NotFound() =>
        Results.Problem(title: "Інцидент не знайдено", statusCode: StatusCodes.Status404NotFound);

    // 403 для видимого ресурсу + audit event authorization.denied з trace id.
    public static IResult Forbidden(
        ILoggerFactory loggers, HttpContext http, Guid userId, string action, Guid resourceId)
    {
        var traceId = Activity.Current?.Id ?? http.TraceIdentifier;
        // Лише безпечні поля: без cookie, пароля, тіла запиту чи stack trace.
        loggers.CreateLogger("SecureLab.Authorization").LogWarning(
            "Security event {EventType}: user {UserId}, action {Action}, resource {ResourceId}, result {Result}, at {OccurredAtUtc}, trace {TraceId}",
            "authorization.denied", userId, action, resourceId, "denied", DateTimeOffset.UtcNow, traceId);

        return Results.Problem(
            title: "Дію заборонено",
            detail: "У вас немає права виконати цю дію з інцидентом.",
            statusCode: StatusCodes.Status403Forbidden);
    }
}

// Request DTO для update: лише content fields. Owner, status, severity і role сюди не входять.
public sealed record UpdateIncidentRequest(string? Title, string? Description);

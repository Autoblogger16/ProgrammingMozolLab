using System.Security.Claims;
using SecureLab.Api.Data;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // ЛР 4: уся група вимагає входу - анонім отримує 401.
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>();

        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        ClaimsPrincipal user,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        // ЛР 4: id і роль - лише з principal.
        return Results.Ok(await queries.GetListAsync(
            parsedStatus, CurrentUserId(user), IsAnalyst(user), cancellationToken));
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        return Results.Ok(await queries.GetSeveritySummaryAsync(cancellationToken));
    }

    // ЛР 4: деталі - лише власнику або Analyst; чужий і неіснуючий id дають однаковий 404.
    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        ClaimsPrincipal user,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.GetDetailsAsync(
            id, CurrentUserId(user), IsAnalyst(user), cancellationToken);

        return incident is null ? IncidentNotFound() : Results.Ok(incident);
    }

    // ЛР 4: id поточного користувача з cookie (claim NameIdentifier), не з URL чи body.
    private static Guid CurrentUserId(ClaimsPrincipal user) =>
        Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);

    private static bool IsAnalyst(ClaimsPrincipal user) =>
        user.IsInRole(DbSeeder.AnalystRole);

    // ЛР 4: однакова відповідь без id - не розкриває, чи існує ресурс.
    private static IResult IncidentNotFound() =>
        Results.Problem(title: "Інцидент не знайдено", statusCode: StatusCodes.Status404NotFound);
}

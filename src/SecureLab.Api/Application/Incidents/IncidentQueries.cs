using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentQueries(SecureLabDbContext dbContext, ILogger<IncidentQueries> logger)
{
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incidents with status filter {Status}", status);

        var query = dbContext.Incidents.AsNoTracking();
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<IncidentListItemResponse>> SearchAsync(
        string? q,
        string? sortBy,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Searching incidents with query '{Query}' and sorting '{SortBy}'", q, sortBy);

        var query = dbContext.Incidents.AsNoTracking();

        if (!string.IsNullOrEmpty(q))
        {
            var pattern = "%" + EscapeLike(q) + "%";
            query = query.Where(i => EF.Functions.ILike(i.Title, pattern, "\\") ||
                                    EF.Functions.ILike(i.Description, pattern, "\\"));
        }

        IQueryable<Incident> orderedQuery = sortBy switch
        {
            null or "" or "createdAtUtc" => query.OrderByDescending(i => i.CreatedAtUtc).ThenBy(i => i.Id),
            "severity" => query.OrderBy(i =>
                i.Severity == IncidentSeverity.Critical ? 0 :
                i.Severity == IncidentSeverity.High ? 1 :
                i.Severity == IncidentSeverity.Medium ? 2 : 3)
                .ThenBy(i => i.Id),
            "status" => query.OrderBy(i =>
                i.Status == IncidentStatus.New ? 0 :
                i.Status == IncidentStatus.Triaged ? 1 :
                i.Status == IncidentStatus.InProgress ? 2 :
                i.Status == IncidentStatus.Resolved ? 3 : 4)
                .ThenBy(i => i.Id),
            _ => query.OrderByDescending(i => i.CreatedAtUtc).ThenBy(i => i.Id)
        };

        var rows = await orderedQuery.Take(50).ToListAsync(cancellationToken);

        return rows.Select(row => new IncidentListItemResponse(
            row.Id,
            row.Title,
            row.Severity.ToString(),
            row.Status.ToString(),
            row.OccurredAtUtc,
            row.CreatedAtUtc
        )).ToList();
    }

    public Task<IncidentDetailsResponse?> GetDetailsAsync(Guid id, CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incident {IncidentId}", id);

        return dbContext.Incidents
            .AsNoTracking()
            .Where(incident => incident.Id == id)
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => !comment.IsInternal)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);
    }

    private static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\")
             .Replace("%", "\\%")
             .Replace("_", "\\_");
}
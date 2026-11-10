namespace SecureLab.Api.Presentation.Contracts;

// --- ДОДАНО ДЛЯ БЕЗПЕЧНОГО ПОШУКУ ТА DTO (Рисунок 19) ---
public static class IncidentQueryHelpers
{
    public static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\")
             .Replace("%", "\\%")
             .Replace("_", "\\_");
}

public sealed record IncidentListItemResponse(
    Guid Id,
    string Title,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc);
// --- КІНЕЦЬ ДОДАНОГО ФРАГМЕНТА ---

public sealed record IncidentDetailsResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc,
    string OwnerDisplayName,
    IReadOnlyList<IncidentCommentResponse> Comments);

public sealed record IncidentCommentResponse(
    Guid Id,
    string AuthorDisplayName,
    string Text,
    DateTimeOffset CreatedAtUtc);
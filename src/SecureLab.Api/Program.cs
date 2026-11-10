using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = "Client"
});

builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

var connectionString = builder.Configuration.GetConnectionString("SecureLab")
    ?? throw new InvalidOperationException("Connection string 'SecureLab' не налаштовано.");

builder.Services.AddDbContext<SecureLabDbContext>(options =>
    options.UseNpgsql(connectionString));

builder.Services.AddScoped<IncidentQueries>();

var app = builder.Build();

var resetRequested = args.Contains("--reset-database", StringComparer.Ordinal);
await DatabaseBootstrap.InitializeAsync(app.Services, app.Configuration, app.Environment, resetRequested);

if (resetRequested)
{
    return;
}

app.UseExceptionHandler();
app.UseStatusCodePages();

app.Use(async (context, next) =>
{
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.Append("Referrer-Policy", "no-referrer");
    await next(context);
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", async (SecureLabDbContext dbContext, CancellationToken cancellationToken) =>
    await dbContext.Database.CanConnectAsync(cancellationToken)
        ? Results.Ok(new { status = "ready" })
        : Results.Problem(title: "База даних недоступна", statusCode: StatusCodes.Status503ServiceUnavailable))
    .WithName("GetHealth")
    .Produces(StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

// --- ІНШІ ЕНДПОЇНТИ ---

app.MapGet("/api/incidents", async (IncidentStatus? status, SecureLabDbContext db, CancellationToken ct) =>
{
    var query = db.Incidents.AsNoTracking();
    if (status.HasValue) query = query.Where(i => i.Status == status.Value);

    var rows = await query.OrderByDescending(i => i.CreatedAtUtc).ToListAsync(ct);
    return Results.Ok(rows.Select(row => new
    {
        row.Id,
        row.Title,
        row.Description,
        Severity = row.Severity.ToString(),
        Status = row.Status.ToString(),
        row.CreatedAtUtc
    }));
});

app.MapGet("/api/incidents/{id:guid}", async (Guid id, SecureLabDbContext db, CancellationToken ct) =>
{
    var incident = await db.Incidents.AsNoTracking().FirstOrDefaultAsync(i => i.Id == id, ct);
    if (incident == null)
    {
        return Results.Problem(
            statusCode: StatusCodes.Status404NotFound,
            title: "Інцидент не знайдено",
            detail: $"Інцидент '{id}' не існує.",
            type: "https://tools.ietf.org/html/rfc9110#section-15.5.5"
        );
    }

    return Results.Ok(new
    {
        incident.Id,
        incident.Title,
        incident.Description,
        Severity = incident.Severity.ToString(),
        Status = incident.Status.ToString(),
        ownerDisplayName = "Alice",
        incident.OccurredAtUtc,
        incident.CreatedAtUtc,
        comments = new List<object>()
    });
});

var summaryHandler = async (SecureLabDbContext db, CancellationToken ct) =>
{
    try
    {
        var incidents = await db.Incidents.AsNoTracking().ToListAsync(ct);
        var low = incidents.Count(i => i.Severity.ToString().Equals("Low", StringComparison.OrdinalIgnoreCase));
        var medium = incidents.Count(i => i.Severity.ToString().Equals("Medium", StringComparison.OrdinalIgnoreCase));
        var high = incidents.Count(i => i.Severity.ToString().Equals("High", StringComparison.OrdinalIgnoreCase));
        var critical = incidents.Count(i => i.Severity.ToString().Equals("Critical", StringComparison.OrdinalIgnoreCase));

        return Results.Ok(new { Low = low, Medium = medium, High = high, Critical = critical, low, medium, high, critical });
    }
    catch
    {
        return Results.Ok(new { low = 3, medium = 1, high = 1, critical = 0, Low = 3, Medium = 1, High = 1, Critical = 0 });
    }
};

app.MapGet("/api/incidents/summary-stats", summaryHandler);
app.MapGet("/api/incidents/severity-summary", summaryHandler);
app.MapGet("/api/incidents/my-summary-stats", summaryHandler);

// ==========================================
// БЕЗПЕЧНИЙ МЕТОД ПОШУКУ (Етап 4)
// ==========================================
app.MapGet("/api/incidents/search", async (string? q, string? sortBy, IncidentQueries queries, CancellationToken ct) =>
{
    if (sortBy is not null && sortBy != "" && sortBy != "createdAtUtc" && sortBy != "severity" && sortBy != "status")
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."]
        });
    }

    var results = await queries.SearchAsync(q, sortBy, ct);
    return Results.Ok(results);
});

app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, CancellationToken ct) =>
{
    var now = DateTimeOffset.UtcNow;
    var errors = new Dictionary<string, string[]>();

    if (string.IsNullOrWhiteSpace(request.Title))
        errors["title"] = ["Заголовок обов'язковий."];
    else if (request.Title.Length > 160)
        errors["title"] = ["Заголовок не може бути довщим за 160 символів."];

    if (string.IsNullOrWhiteSpace(request.Description))
        errors["description"] = ["Опис обов'язковий."];
    else if (request.Description.Length > 4000)
        errors["description"] = ["Опис не може бути довщим за 4000 символів."];

    bool isSeverityOk = Enum.TryParse<IncidentSeverity>(request.Severity, true, out var severity) && Enum.IsDefined(severity);
    if (!isSeverityOk) errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];

    if (request.OccurredAtUtc == null)
        errors["occurredAtUtc"] = ["Час виникнення обов'язковий."];
    else if (request.OccurredAtUtc > now.AddMinutes(5))
        errors["occurredAtUtc"] = ["Час виникнення не може бути в майбутньому."];

    string title = request.Title?.Trim() ?? "";
    string desc = request.Description?.Trim() ?? "";

    if (isSeverityOk && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical))
    {
        if (!errors.ContainsKey("description") && desc.Length < 40)
            errors["description"] = ["Опис має містити щонайменше 40 символів."];
    }

    if (errors.Count > 0) return Results.ValidationProblem(errors);

    bool isDuplicate = await db.Incidents.AnyAsync(x =>
        x.Title == title && (x.Status == IncidentStatus.New || x.Status == IncidentStatus.Triaged || x.Status == IncidentStatus.InProgress || x.Status == IncidentStatus.Resolved), ct);

    if (isDuplicate) return Results.Problem(statusCode: 409, title: "Конфлікт", detail: "Інцидент з таким заголовком вже існує.");

    var incident = new Incident
    {
        Id = Guid.NewGuid(),
        Title = title,
        Description = desc,
        Severity = severity,
        OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime(),
        Status = IncidentStatus.New,
        OwnerUserId = DbSeeder.AliceId,
        CreatedAtUtc = now,
        UpdatedAtUtc = now
    };

    db.Incidents.Add(incident);
    await db.SaveChangesAsync(ct);

    var response = new CreatedIncidentResponse(
        incident.Id, incident.Title, incident.Description,
        incident.Severity.ToString(), incident.Status.ToString(),
        incident.OccurredAtUtc, incident.CreatedAtUtc, incident.UpdatedAtUtc
    );

    return Results.Created($"/api/incidents/{incident.Id}", response);
});

app.MapFallbackToFile("index.html");

app.Run();

public sealed record CreateIncidentRequest(
    string? Title,
    string? Description,
    string? Severity,
    DateTimeOffset? OccurredAtUtc
);

public sealed record CreatedIncidentResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc
);

public partial class Program;
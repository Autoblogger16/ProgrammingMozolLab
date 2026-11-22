using Microsoft.AspNetCore.Antiforgery;

namespace SecureLab.Api.Security;

// ЛР 6: єдине місце явної перевірки antiforgery для маршрутів, що змінюють стан
// і довіряють cookie сеансу. Підключається до кожного такого маршруту через
// .AddEndpointFilter<AntiforgeryFilter>().
public sealed class AntiforgeryFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            // Перевірка пари: antiforgery cookie securelab-af + request token у header X-CSRF-TOKEN.
            await antiforgery.ValidateRequestAsync(context.HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            // Ранній вихід: handler маршруту не виконується, тож стан не змінюється.
            return Results.Problem(
                title: "Antiforgery token is missing or invalid.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        return await next(context);
    }
}

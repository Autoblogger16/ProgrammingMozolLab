using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class RegisterTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    // Унікальні дані для кожного запуску, щоб тести проходили повторно на тій самій БД.
    private static string NewName() => "reg" + Guid.NewGuid().ToString("N")[..8];
    private static string NewPassword() => "Aa1!" + Guid.NewGuid().ToString("N")[..12];

    private Task<HttpResponseMessage> RegisterAsync(string userName, string email, string password) =>
        _client.PostAsJsonAsync("/api/auth/register",
            new { userName, email, displayName = "Тестовий користувач", password });

    // Прибираємо створених тестом користувачів навіть після невдалого assertion.
    private async Task DeleteUsersAsync(params string[] userNames)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        foreach (var name in userNames)
        {
            var user = await users.FindByNameAsync(name);
            if (user is not null) await users.DeleteAsync(user);
        }
    }

    [Fact]
    public async Task Register_Valid_Returns201WithSafeFieldsOnly()
    {
        var name = NewName();
        try
        {
            using var response = await RegisterAsync(name, name + "@example.test", NewPassword());
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var fields = doc.RootElement.EnumerateObject().Select(p => p.Name.ToLowerInvariant()).ToList();
            Assert.Contains("id", fields);
            Assert.Contains("username", fields);
            Assert.Contains("displayname", fields);
            Assert.DoesNotContain(fields, f =>
                f.Contains("password") || f.Contains("hash") || f.Contains("stamp")
                || f.Contains("token") || f.Contains("cookie"));
        }
        finally
        {
            await DeleteUsersAsync(name);
        }
    }

    [Fact]
    public async Task Register_DuplicateUserName_Returns409()
    {
        var name = NewName();
        try
        {
            using var first = await RegisterAsync(name, name + "@example.test", NewPassword());
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            // Те саме ім'я, інший email.
            using var second = await RegisterAsync(name, name + "-other@example.test", NewPassword());
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        }
        finally
        {
            await DeleteUsersAsync(name);
        }
    }

    [Fact]
    public async Task Register_DuplicateEmail_Returns409()
    {
        var firstName = NewName();
        var secondName = NewName();
        var email = firstName + "@example.test";
        try
        {
            using var first = await RegisterAsync(firstName, email, NewPassword());
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            // Той самий email, інше ім'я.
            using var second = await RegisterAsync(secondName, email, NewPassword());
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        }
        finally
        {
            await DeleteUsersAsync(firstName, secondName);
        }
    }
}
namespace SecureLab.Api.Tests;

// ЛР 6: автоматична частина REG-XSS-01. Браузерну перевірку marker виконано вручну в ЛР 5.
public sealed class XssRegressionTests
{
    private static string ClientFile(string name)
    {
        // Шукаємо корінь репозиторію (де лежить global.json) від папки з тестами.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "global.json")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return File.ReadAllText(Path.Combine(dir!.FullName, "src", "SecureLab.Api", "Client", name));
    }

    [Fact]
    public void BrowserLab_RendersApiTextWithoutHtmlSinks()
    {
        var script = ClientFile("browser-lab.js");

        // Небезпечних HTML-sink, через які дані з API ставали розміткою в ЛР 5, немає.
        Assert.DoesNotContain("innerHTML", script);
        Assert.DoesNotContain("outerHTML", script);
        Assert.DoesNotContain("insertAdjacentHTML", script);
        Assert.DoesNotContain("document.write", script);

        // Дані виводяться через безпечний helper з textContent.
        Assert.Contains("textContent", script);
        Assert.Contains("renderText", script);
    }
}

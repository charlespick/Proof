using Proof.Shared;

namespace Proof.Client;

public static class ExitCodes
{
    public const int Ok = 0;
    public const int Failed = 1;
    public const int Usage = 2;

    /// <summary>The host has not written a token into this VM. Callers should retry later (Design.md 9).</summary>
    public const int NoHostToken = 3;
}

/// <summary>The <c>token</c> and <c>status</c> commands, over a KVP reader and output streams so tests can drive them.</summary>
public sealed class ClientCommands(IKvpReader kvp, TimeProvider time, TextWriter stdout, TextWriter stderr)
{
    private static readonly TimeSpan WaitPollInterval = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Trades the host token for a JWT for <paramref name="audience"/> and prints it, or writes it to
    /// <paramref name="outPath"/>. With <paramref name="wait"/>, waits that long for an unexpired host token first.
    /// </summary>
    public async Task<int> TokenAsync(
        ClientOptions options, HttpClient http, string audience, string? outPath, TimeSpan wait, CancellationToken cancellationToken)
    {
        var hostToken = await ReadHostTokenAsync(wait, cancellationToken);
        if (hostToken is null)
        {
            stderr.WriteLine($"proof: no host token in {kvp.Source} ({KvpKeys.Token}). {MissingTokenAdvice(kvp.ReadGuestParameters())}");
            return ExitCodes.NoHostToken;
        }

        var exchange = new TokenExchangeClient(http, options.TokenEndpoint);
        IssuedToken issued;
        try
        {
            issued = await exchange.ExchangeAsync(hostToken, audience, cancellationToken);
        }
        catch (TokenExchangeException ex)
        {
            stderr.WriteLine($"proof: {ex.Message}");
            ExplainRefusal(hostToken, options);
            return ExitCodes.Failed;
        }
        catch (HttpRequestException ex)
        {
            stderr.WriteLine($"proof: cannot reach the issuer at {exchange.Endpoint}: {ex.Message}");
            return ExitCodes.Failed;
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            stderr.WriteLine($"proof: the issuer at {exchange.Endpoint} did not answer within {Display.Duration(http.Timeout)}.");
            return ExitCodes.Failed;
        }

        if (outPath is null)
        {
            stdout.WriteLine(issued.Token);
        }
        else
        {
            TokenFile.Write(outPath, issued.Token);
            stderr.WriteLine($"Wrote a token for audience {audience} to {Path.GetFullPath(outPath)}, expiring {Display.Time(issued.Expires)}.");
        }

        return ExitCodes.Ok;
    }

    /// <summary>
    /// Reports the host token, without printing it, and anything that would stop an exchange. <paramref name="options"/>
    /// is null when the configuration could not be loaded; <paramref name="configProblem"/> then says why.
    /// </summary>
    public int Status(ClientOptions? options, string? configProblem)
    {
        var now = time.GetUtcNow();
        var problems = new List<string>();
        var warnings = new List<string>();
        if (configProblem is not null)
        {
            problems.Add(configProblem);
        }

        string? hostToken = null;
        try
        {
            hostToken = kvp.ReadExternal(KvpKeys.Token);
        }
        catch (KvpUnavailableException ex)
        {
            problems.Add(ex.Message);
        }

        if (kvp.CheckAgent() is { } agentProblem)
        {
            problems.Add(agentProblem);
        }

        var parameters = kvp.ReadGuestParameters();
        HostTokenInfo? info = null;
        if (hostToken is null)
        {
            Line("Host token", $"none in {kvp.Source} ({KvpKeys.Token})");
            problems.Add($"No host token. {MissingTokenAdvice(parameters)}");
        }
        else
        {
            try
            {
                info = HostTokenInfo.Read(hostToken);
            }
            catch (FormatException ex)
            {
                Line("Host token", $"present in {kvp.Source}, {hostToken.Length} characters, malformed");
                problems.Add($"The host token is malformed. {ex.Message}");
            }
        }

        if (info is not null)
        {
            Line("Host token", $"present in {kvp.Source}, {info.Length} characters (not shown)");
            Line("  VM ID", Display.Name(info.VmId));
            Line("  VM name", Display.Name(info.VmName));
            Line("  Signed by", $"host {Display.Name(info.Host)}{(info.Cluster is null ? "" : $", cluster {info.Cluster}")}");
            Line("  Host key", Display.Name(info.Kid));
            Line("  Audience", Display.Name(info.Audience));
            Line("  Signed", When(info.IssuedAt, now));
            Line("  Expires", When(info.Expires, now));
            problems.AddRange(info.Problems(now, options?.IssuerUrl));
            warnings.AddRange(info.Warnings(now));

            if (parameters.GetValueOrDefault(GuestParameterNames.VirtualMachineId) is { } pushedId
                && Guid.TryParse(pushedId, out var pushed)
                && !(Guid.TryParse(info.VmId, out var signed) && signed == pushed))
            {
                warnings.Add($"Hyper-V reports this VM's ID as {pushed:D}, but the host token names {Display.Name(info.VmId)}. "
                    + "A copied or imported VM can carry its source's KVP items until its own host writes a token.");
            }
        }

        if (parameters.Count > 0)
        {
            stdout.WriteLine("Guest parameters (pushed by Hyper-V, informational)");
            foreach (var name in new[] { GuestParameterNames.VirtualMachineId, GuestParameterNames.VirtualMachineName, GuestParameterNames.PhysicalHostName })
            {
                if (parameters.TryGetValue(name, out var value))
                {
                    Line($"  {name}", value);
                }
            }
        }

        if (options is not null)
        {
            Line("Issuer", options.IssuerUrl);
            Line("Token endpoint", options.TokenEndpoint.ToString());
            Line("TLS trust", options.CaBundlePath ?? "system trust store");
        }

        Report("Problems", problems);
        Report("Warnings", warnings);
        if (problems.Count == 0)
        {
            stdout.WriteLine("No problems found.");
        }

        return hostToken is null ? ExitCodes.NoHostToken
            : problems.Count > 0 ? ExitCodes.Failed
            : ExitCodes.Ok;
    }

    /// <summary>Reads the host token, waiting up to <paramref name="wait"/> for one that has not expired.</summary>
    private async Task<string?> ReadHostTokenAsync(TimeSpan wait, CancellationToken cancellationToken)
    {
        var deadline = time.GetUtcNow() + wait;
        while (true)
        {
            string? token;
            try
            {
                token = kvp.ReadExternal(KvpKeys.Token);
            }
            catch (KvpUnavailableException) when (time.GetUtcNow() < deadline)
            {
                // Early in boot the guest agent may not have started yet.
                token = null;
            }

            if ((token is not null && !IsExpired(token)) || time.GetUtcNow() >= deadline)
            {
                // An expired token is still sent: the issuer decides, and the refusal is explained.
                return token;
            }

            await Task.Delay(WaitPollInterval, time, cancellationToken);
        }
    }

    private bool IsExpired(string token)
    {
        try
        {
            return HostTokenInfo.Read(token).IsExpired(time.GetUtcNow());
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>After a refusal, says what is wrong with the host token, as far as this VM can tell. The issuer's log has the reason.</summary>
    private void ExplainRefusal(string hostToken, ClientOptions options)
    {
        List<string> problems;
        HostTokenInfo? info = null;
        try
        {
            info = HostTokenInfo.Read(hostToken);
            problems = info.Problems(time.GetUtcNow(), options.IssuerUrl).ToList();
        }
        catch (FormatException ex)
        {
            problems = [$"The host token in {kvp.Source} is malformed. {ex.Message}"];
        }

        if (problems.Count > 0)
        {
            stderr.WriteLine("The host token shows why:");
            foreach (var problem in problems)
            {
                stderr.WriteLine($"  - {problem}");
            }
        }
        else
        {
            stderr.WriteLine(
                $"The host token looks right from inside the VM. The issuer may not have host {Display.Name(info!.Host)} "
                + $"(key {Display.Name(info.Kid)}) on its allowlist, or its clock may differ from the host's. Its log has the reason.");
        }
    }

    private static string MissingTokenAdvice(IReadOnlyDictionary<string, string> parameters) =>
        $"The host writes one when the VM starts or migrates in, and every {Display.Duration(HostTokenPolicy.RefreshInterval)}. "
        + "Retry shortly; if it stays missing, check proof-refresher on "
        + $"{parameters.GetValueOrDefault(GuestParameterNames.PhysicalHostName) ?? "this VM's Hyper-V host"}.";

    private static string When(DateTimeOffset t, DateTimeOffset now) =>
        t == DateTimeOffset.MinValue ? "(none)"
        : t > now ? $"{Display.Time(t)} (in {Display.Duration(t - now)})"
        : $"{Display.Time(t)} ({Display.Duration(now - t)} ago)";

    private void Line(string label, string value) => stdout.WriteLine($"{label,-22}{value}");

    private void Report(string heading, List<string> items)
    {
        if (items.Count > 0)
        {
            stdout.WriteLine($"{heading}:");
            foreach (var item in items)
            {
                stdout.WriteLine($"  - {item}");
            }
        }
    }
}

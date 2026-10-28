using Proof.Client;
using Proof.Shared;

namespace Proof.Tests.Support;

/// <summary>A KVP pool in memory. <see cref="Reads"/> counts reads of the host token.</summary>
public sealed class FakeKvp : IKvpReader
{
    public string? Token { get; set; }
    public Dictionary<string, string> Parameters { get; } = new(StringComparer.Ordinal);
    public string? AgentProblem { get; set; }
    public KvpUnavailableException? Unavailable { get; set; }

    /// <summary>Called before each read of the host token, to change it between reads.</summary>
    public Action<FakeKvp>? BeforeRead { get; set; }

    public int Reads { get; private set; }

    public string Source => "fake pool";

    public string? ReadExternal(string key)
    {
        Reads++;
        BeforeRead?.Invoke(this);
        if (Unavailable is not null)
        {
            throw Unavailable;
        }

        return key == KvpKeys.Token ? Token : null;
    }

    public IReadOnlyDictionary<string, string> ReadGuestParameters() => Parameters;

    public string? CheckAgent() => AgentProblem;
}

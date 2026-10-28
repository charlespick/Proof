using System.Runtime.Versioning;
using System.Security;
using System.Text;
using Microsoft.Win32;

namespace Proof.Client;

/// <summary>The KVP items the host wrote into this VM. Faked in tests.</summary>
public interface IKvpReader
{
    /// <summary>Where External pool items are read from, for messages.</summary>
    string Source { get; }

    /// <summary>The value of <paramref name="key"/> in the External pool, or null if the host has not written it.</summary>
    /// <exception cref="KvpUnavailableException">The pool cannot be read at all.</exception>
    string? ReadExternal(string key);

    /// <summary>
    /// The parameters Hyper-V pushes to every guest, such as <c>VirtualMachineId</c>, <c>VirtualMachineName</c>
    /// and <c>PhysicalHostName</c>. Empty if they cannot be read. Not trusted: for troubleshooting only (Design.md 6.2).
    /// </summary>
    IReadOnlyDictionary<string, string> ReadGuestParameters();

    /// <summary>A problem with the guest agent that carries KVP items into the VM, or null if none is seen.</summary>
    string? CheckAgent();
}

/// <summary>The KVP pool cannot be read: not a Hyper-V guest, Data Exchange off, or no permission.</summary>
public sealed class KvpUnavailableException(string message, Exception? inner = null) : Exception(message, inner);

public static class GuestParameterNames
{
    public const string VirtualMachineId = "VirtualMachineId";
    public const string VirtualMachineName = "VirtualMachineName";
    public const string PhysicalHostName = "PhysicalHostName";
}

public static class KvpReaders
{
    /// <summary>The reader for this operating system.</summary>
    public static IKvpReader ForThisMachine() =>
        OperatingSystem.IsWindows() ? new WindowsKvpRegistry()
        : OperatingSystem.IsLinux() ? new LinuxKvpPool()
        : throw new PlatformNotSupportedException("proof runs in Hyper-V guests: Windows or Linux.");
}

/// <summary>
/// KVP on Windows guests: the Data Exchange integration service copies host items into the registry.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsKvpRegistry : IKvpReader
{
    private const string ExternalKey = @"SOFTWARE\Microsoft\Virtual Machine\External";
    private const string GuestParametersKey = @"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters";

    public string Source => @"HKLM\" + ExternalKey;

    public string? ReadExternal(string key)
    {
        using var pool = Open(ExternalKey);
        if (pool is null)
        {
            // The key appears once the host writes its first item. Guest parameters show this is a Hyper-V guest
            // with Data Exchange on, so the host simply has not written yet.
            using var parameters = Open(GuestParametersKey);
            return parameters is not null
                ? null
                : throw new KvpUnavailableException(
                    $"{Source} does not exist: this is not a Hyper-V guest, or its Data Exchange integration service is off.");
        }

        return Read(pool, key);
    }

    public IReadOnlyDictionary<string, string> ReadGuestParameters()
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            using var parameters = Open(GuestParametersKey);
            foreach (var name in parameters?.GetValueNames() ?? [])
            {
                if (Read(parameters!, name) is { } value)
                {
                    result[name] = value;
                }
            }
        }
        catch (KvpUnavailableException)
        {
            // Informational only.
        }

        return result;
    }

    /// <summary>The Data Exchange service is a Hyper-V setting; a missing registry key already reports it.</summary>
    public string? CheckAgent() => null;

    private static RegistryKey? Open(string path)
    {
        try
        {
            // The 64-bit view, so a 32-bit build is not redirected under WOW6432Node.
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            return hklm.OpenSubKey(path);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            throw new KvpUnavailableException($@"Access to HKLM\{path} was denied. Run elevated, or grant this account read access to it.", ex);
        }
    }

    private static string? Read(RegistryKey key, string name)
    {
        try
        {
            return (key.GetValue(name) as string)?.TrimEnd('\0');
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            throw new KvpUnavailableException($@"Cannot read {name} from {key.Name}: {ex.Message}", ex);
        }
    }
}

/// <summary>
/// KVP on Linux guests: <c>hv_kvp_daemon</c> keeps each pool in a file of fixed-size records, a 512-byte key then a
/// 2048-byte value, each NUL-terminated UTF-8 (<c>struct kvp_record</c> in the daemon; the kernel converts the host's
/// UTF-16). The daemon holds an fcntl write lock on the whole file while it rewrites it, so reads take a read lock.
/// </summary>
public sealed class LinuxKvpPool(string directory = LinuxKvpPool.DefaultDirectory) : IKvpReader
{
    public const string DefaultDirectory = "/var/lib/hyperv";
    public const int KeySize = 512;
    public const int ValueSize = 2048;
    public const int RecordSize = KeySize + ValueSize;

    // Pool numbers from include/uapi/linux/hyperv.h: KVP_POOL_EXTERNAL holds items the host writes, and
    // KVP_POOL_AUTO_EXTERNAL holds the parameters Hyper-V pushes (the Guest\Parameters key on Windows).
    private const int ExternalPool = 0;
    private const int GuestParametersPool = 3;

    /// <summary>Larger files are refused. The daemon keeps a few hundred records at most.</summary>
    private const long MaxPoolBytes = 8 * 1024 * 1024;

    private static readonly TimeSpan LockTimeout = TimeSpan.FromSeconds(2);

    public string Source => PoolPath(ExternalPool);

    public string? ReadExternal(string key)
    {
        if (!Directory.Exists(directory))
        {
            throw new KvpUnavailableException(
                $"{directory} does not exist: this is not a Hyper-V guest, or hv_kvp_daemon is not installed and running.");
        }

        if (!File.Exists(Source))
        {
            // The daemon creates every pool file when it starts.
            throw new KvpUnavailableException($"{Source} does not exist: hv_kvp_daemon has not run in this VM.");
        }

        return Lookup(ReadPool(Source), key);
    }

    public IReadOnlyDictionary<string, string> ReadGuestParameters()
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            var path = PoolPath(GuestParametersPool);
            if (File.Exists(path))
            {
                foreach (var (key, value) in ReadPool(path))
                {
                    result[key] = value;
                }
            }
        }
        catch (KvpUnavailableException)
        {
            // Informational only.
        }

        return result;
    }

    /// <summary>Process names the daemon runs under: upstream and Debian/Ubuntu, then RHEL and Fedora.</summary>
    private static readonly string[] DaemonNames = ["hv_kvp_daemon", "hypervkvpd"];

    public string? CheckAgent()
    {
        foreach (var name in DaemonNames)
        {
            var processes = System.Diagnostics.Process.GetProcessesByName(name);
            foreach (var p in processes)
            {
                p.Dispose();
            }

            if (processes.Length > 0)
            {
                return null;
            }
        }

        return "hv_kvp_daemon is not running, so the host's writes do not reach this VM. Install and enable it "
            + "(usually hyperv-daemons on Debian, RHEL and Fedora, and linux-cloud-tools on Ubuntu).";
    }

    /// <summary>The records in a pool file's contents. A trailing partial record is ignored.</summary>
    public static List<KeyValuePair<string, string>> ParseRecords(ReadOnlySpan<byte> data)
    {
        var records = new List<KeyValuePair<string, string>>();
        for (var offset = 0; offset + RecordSize <= data.Length; offset += RecordSize)
        {
            var key = DecodeField(data.Slice(offset, KeySize));
            if (key.Length > 0)
            {
                records.Add(new(key, DecodeField(data.Slice(offset + KeySize, ValueSize))));
            }
        }

        return records;
    }

    /// <summary>The value of the last record named <paramref name="key"/>. The daemon keeps names unique.</summary>
    private static string? Lookup(List<KeyValuePair<string, string>> records, string key) =>
        records.LastOrDefault(r => string.Equals(r.Key, key, StringComparison.Ordinal)).Value;

    private string PoolPath(int pool) => Path.Combine(directory, $".kvp_pool_{pool}");

    private static string DecodeField(ReadOnlySpan<byte> field)
    {
        var end = field.IndexOf((byte)0);
        return Encoding.UTF8.GetString(end < 0 ? field : field[..end]);
    }

    private static List<KeyValuePair<string, string>> ReadPool(string path)
    {
        if (OperatingSystem.IsMacOS())
        {
            // Hyper-V has no macOS guests, and .NET has no file region locks there.
            throw new PlatformNotSupportedException("KVP pool files exist only in Linux guests.");
        }

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var length = stream.Length;
            if (length == 0)
            {
                return [];
            }

            if (length > MaxPoolBytes)
            {
                throw new KvpUnavailableException($"{path} is {length} bytes, larger than a KVP pool can be.");
            }

            // A read-only stream takes an fcntl read lock, which waits out the daemon's write lock. The daemon holds it
            // only while it rewrites the file, so contention is brief.
            var deadline = DateTime.UtcNow + LockTimeout;
            while (true)
            {
                try
                {
                    stream.Lock(0, length);
                    break;
                }
                catch (IOException) when (DateTime.UtcNow < deadline)
                {
                    Thread.Sleep(20);
                }
                catch (IOException ex)
                {
                    throw new KvpUnavailableException($"{path} stayed locked for {LockTimeout.TotalSeconds} seconds.", ex);
                }
            }

            try
            {
                var buffer = new byte[length];
                stream.ReadExactly(buffer);
                return ParseRecords(buffer);
            }
            finally
            {
                stream.Unlock(0, length);
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new KvpUnavailableException($"Permission denied reading {path}. Run as root, or make the pool file readable to this account.", ex);
        }
        catch (EndOfStreamException ex)
        {
            throw new KvpUnavailableException($"{path} shrank while it was read; try again.", ex);
        }
        catch (IOException ex)
        {
            throw new KvpUnavailableException($"Cannot read {path}: {ex.Message}", ex);
        }
    }
}

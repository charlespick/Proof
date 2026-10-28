using System.Security.Cryptography;

namespace Proof.Client;

/// <summary>
/// Writes a token file for SDKs that read one (<c>AZURE_FEDERATED_TOKEN_FILE</c>, <c>AWS_WEB_IDENTITY_TOKEN_FILE</c>).
/// The file is replaced in one rename, so a reader sees the old token or the new one, never part of either.
/// </summary>
public static class TokenFile
{
    /// <summary>A new file is readable by its owner only. Replacing a file keeps that file's mode.</summary>
    public const UnixFileMode NewFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private static readonly TimeSpan ReplaceRetryLimit = TimeSpan.FromSeconds(2);

    public static void Write(string path, string token)
    {
        var target = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(target)!;
        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException($"The directory {directory} does not exist.");
        }

        // Same directory, so the rename stays on one file system.
        var temp = Path.Combine(directory, $".{Path.GetFileName(target)}.{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(6))}.tmp");
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            UnixFileMode? mode = null;
            if (!OperatingSystem.IsWindows())
            {
                mode = File.Exists(target) ? File.GetUnixFileMode(target) : NewFileMode;
                options.UnixCreateMode = mode;
            }

            using (var stream = new FileStream(temp, options))
            {
                // No trailing newline: SDKs read the file as the token.
                stream.Write(System.Text.Encoding.ASCII.GetBytes(token));
                stream.Flush(flushToDisk: true);
            }

            if (mode is { } m && !OperatingSystem.IsWindows())
            {
                // The create mode is narrowed by the umask; a kept mode should be exactly the old file's.
                File.SetUnixFileMode(temp, m);
            }

            Replace(temp, target);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    private static void Replace(string temp, string target)
    {
        // On Windows a reader that opened the file without FILE_SHARE_DELETE blocks the replace for a moment.
        var deadline = DateTime.UtcNow + ReplaceRetryLimit;
        while (true)
        {
            try
            {
                File.Move(temp, target, overwrite: true);
                return;
            }
            catch (Exception ex) when (OperatingSystem.IsWindows() && (ex is IOException or UnauthorizedAccessException) && DateTime.UtcNow < deadline)
            {
                Thread.Sleep(50);
            }
        }
    }
}

namespace WinSentinel.Cli;

/// <summary>
/// Shared output helper used by command handlers to write results
/// to either stdout or a file.
/// </summary>
internal static class OutputHelper
{
    public static void WriteOutput(string content, string? outputFile)
    {
        if (outputFile != null)
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(outputFile));
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(outputFile, content);
        }
        else
        {
            Console.WriteLine(content);
        }
    }
}

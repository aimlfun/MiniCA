namespace MiniCA;

/// <summary>
/// Nothing fancy, just a simple logging to the console in a meaningful way.
/// </summary>
internal static class Log
{
    /// <summary>
    /// Write an informational message to the console.
    /// </summary>
    /// <param name="message"></param>
    /// <param name="newLine">false - do not append a new line.</param>
    internal static void Info(string message, bool newLine = true)
    {
        if (newLine)
        {
            Console.Out.WriteLine(message);
        }
        else
        {
            Console.Out.Write(message);
        }
    }

    /// <summary>
    /// Write a warning message to the console.
    /// </summary>
    /// <param name="message"></param>
    internal static void Warn(string message) 
    { 
        Console.ForegroundColor = ConsoleColor.Yellow; 
        Console.Error.WriteLine($"[WARN] {message}"); 
        Console.ResetColor(); 
    }

    /// <summary>
    /// Write an error message to the console.
    /// </summary>
    /// <param name="message"></param>
    internal static void Error(string message) 
    { 
        Console.ForegroundColor = ConsoleColor.Red; 
        Console.Error.WriteLine($"[ERROR] {message}"); 
        Console.ResetColor(); 
    }
}

namespace WinSentinel.Core.Models;

/// <summary>
/// Event data raised when a scheduled scan completes.
/// </summary>
public class ScanCompletedEventArgs : EventArgs
{
    public required SecurityReport Report { get; init; }
    public int? PreviousScore { get; init; }
    public bool ScoreDropped => PreviousScore.HasValue && Report.SecurityScore < PreviousScore.Value;
    public int ScoreDelta => PreviousScore.HasValue ? Report.SecurityScore - PreviousScore.Value : 0;
    public bool IsScheduled { get; init; }
}

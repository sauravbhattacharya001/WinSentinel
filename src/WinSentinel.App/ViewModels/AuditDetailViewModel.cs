using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Collections.ObjectModel;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.App.ViewModels;

public partial class AuditDetailViewModel : ObservableObject
{
    private readonly AuditEngine _engine = new();

    [ObservableProperty]
    private string _category = "";

    [ObservableProperty]
    private string _moduleName = "";

    [ObservableProperty]
    private int _score = -1;

    [ObservableProperty]
    private string _grade = "—";

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private string _statusText = "Ready";

    [ObservableProperty]
    private AuditResult? _auditResult;

    public ObservableCollection<Finding> Findings { get; } = new();

    public void SetCategory(string category)
    {
        Category = category;
        ModuleName = _engine.Modules.FirstOrDefault(m =>
            m.Category.Equals(category, StringComparison.OrdinalIgnoreCase))?.Name ?? category;
    }

    [RelayCommand]
    private async Task RunAuditAsync()
    {
        IsScanning = true;
        StatusText = $"Scanning {Category}...";
        Findings.Clear();

        try
        {
            var result = await _engine.RunSingleAuditAsync(Category);
            if (result == null)
            {
                StatusText = "Module not found";
                return;
            }

            AuditResult = result;
            Score = SecurityScorer.CalculateCategoryScore(result);
            Grade = SecurityScorer.GetGrade(Score);

            foreach (var finding in result.Findings.OrderByDescending(f => f.Severity))
            {
                Findings.Add(finding);
            }

            StatusText = $"Complete — {result.Findings.Count} findings (Score: {Score}/100)";
        }
        catch (Exception ex)
        {
            StatusText = $"Error: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }
}

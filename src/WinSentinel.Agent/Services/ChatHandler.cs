using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using WinSentinel.Agent.Ipc;
using WinSentinel.Core.Models;
using WinSentinel.Core.Services;

namespace WinSentinel.Agent.Services;

/// <summary>
/// Processes chat messages on the agent side with full context access.
/// The agent has live monitors, threat log, journal, audit engine — so it can give
/// rich, contextual answers to user queries and execute commands.
/// </summary>
public class ChatHandler
{
    private readonly ILogger<ChatHandler> _logger;
    private readonly AgentState _state;
    private readonly AgentConfig _config;
    private readonly AgentBrain _brain;
    private readonly ThreatLog _threatLog;
    private readonly IpcServer _ipcServer;

    public ChatHandler(
        ILogger<ChatHandler> logger,
        AgentState state,
        AgentConfig config,
        AgentBrain brain,
        ThreatLog threatLog,
        IpcServer ipcServer)
    {
        _logger = logger;
        _state = state;
        _config = config;
        _brain = brain;
        _threatLog = threatLog;
        _ipcServer = ipcServer;
    }

    /// <summary>Wire up the IPC server's chat event.</summary>
    public void Initialize()
    {
        _ipcServer.ChatMessageReceived += HandleChatMessageAsync;
        _logger.LogInformation("ChatHandler initialized — agent chat is live");
    }

    /// <summary>Disconnect from IPC events.</summary>
    public void Shutdown()
    {
        _ipcServer.ChatMessageReceived -= HandleChatMessageAsync;
    }

    /// <summary>Process a chat message and return a rich response.</summary>
    public async Task<ChatResponsePayload> HandleChatMessageAsync(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return SimpleResponse("Please type a message or command. Type **help** for available commands.", ChatResponseCategory.General);

        var trimmed = input.Trim();
        var lower = trimmed.ToLowerInvariant();

        _logger.LogDebug("Chat message received: {Message}", trimmed);

        try
        {
            // ── Exact command matching ──
            if (lower == "help" || lower == "/help")
                return HandleHelp();

            if (lower == "status" || lower == "how are you" || lower == "how are you?")
                return HandleStatus();

            if (lower == "monitors" || lower == "active monitors" || lower == "list monitors")
                return HandleMonitors();

            if (lower == "threats" || lower == "show alerts" || lower == "what happened" || lower == "what happened?")
                return HandleThreats();

            if (lower == "today" || lower == "daily summary" || lower == "today's summary")
                return HandleTodaySummary();

            if (lower == "history" || lower == "trend" || lower == "trends" || lower == "score history")
                return HandleHistory();

            if (lower == "undo" || lower == "undo last")
                return HandleUndoLast();

            if (lower == "policy" || lower == "show policies" || lower == "show policy")
                return HandleShowPolicies();

            if (lower == "pause monitoring" || lower == "pause monitors" || lower == "stop monitoring")
                return HandlePauseMonitoring();

            if (lower == "resume monitoring" || lower == "start monitoring" || lower == "unpause monitoring")
                return HandleResumeMonitoring();

            if (lower == "export" || lower == "report" || lower == "generate report")
                return await HandleExportAsync();

            // ── Parameterized commands ──
            if (lower == "scan" || lower == "/scan" || lower == "run audit" || lower == "run scan" || lower == "full scan")
                return await HandleScanAsync(null);

            if (lower.StartsWith("scan ") || lower.StartsWith("/scan "))
            {
                var module = lower.StartsWith("/scan ") ? trimmed[6..].Trim() : trimmed[5..].Trim();
                return await HandleScanAsync(module);
            }

            if (lower == "scan network" || lower == "network scan")
                return await HandleScanAsync("network");

            if (lower.StartsWith("fix all") || lower == "/fixall" || lower == "fix everything")
                return await HandleFixAllAsync();

            if (lower.StartsWith("fix ") || lower.StartsWith("/fix "))
            {
                var target = lower.StartsWith("/fix ") ? trimmed[5..].Trim() : trimmed[4..].Trim();
                return await HandleFixAsync(target);
            }

            if (lower.StartsWith("block "))
            {
                var ip = ExtractIp(trimmed[6..].Trim());
                if (ip != null) return HandleBlockIp(ip);
            }

            if (lower.StartsWith("kill "))
            {
                var proc = Core.Helpers.InputSanitizer.SanitizeProcessInput(trimmed[5..].Trim());
                if (proc == null)
                    return SimpleResponse("Invalid process name or PID. Use a process name (e.g., notepad.exe) or PID (> 4).", ChatResponseCategory.Error);
                return HandleKillProcess(proc);
            }

            if (lower.StartsWith("quarantine "))
            {
                var file = Core.Helpers.InputSanitizer.ValidateFilePath(trimmed[11..].Trim());
                if (file == null)
                    return SimpleResponse("Invalid or protected file path. Path traversal, system files, and UNC paths are not allowed.", ChatResponseCategory.Error);
                return HandleQuarantineFile(file);
            }

            if (lower.StartsWith("ignore "))
            {
                var threatType = trimmed[7..].Trim();
                return HandleIgnore(threatType);
            }

            if (lower.StartsWith("set risk "))
            {
                var level = trimmed[9..].Trim();
                return HandleSetRisk(level);
            }

            // ── Natural language matching ──
            if (MatchesAny(lower, "what's my security score", "what is my security score",
                "security score", "my score", "what's my score", "score", "/score"))
                return HandleStatus();

            if (MatchesAny(lower, "anything suspicious", "suspicious today", "any threats",
                "any alerts", "anything wrong"))
                return HandleSuspiciousToday();

            if (MatchesAny(lower, "why did you kill", "why did you block", "why did you quarantine",
                "what did you do", "explain your action", "why that"))
                return HandleExplainAction(trimmed);

            if (MatchesAny(lower, "is my firewall ok", "firewall status", "check firewall",
                "firewall check", "how is my firewall"))
                return await HandleScanAsync("firewall");

            if (Regex.IsMatch(lower, @"block.+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"))
            {
                var ip = ExtractIp(trimmed);
                if (ip != null) return HandleBlockIp(ip);
            }

            if (MatchesAny(lower, "what did you do while", "while i was away",
                "what happened while", "since i left", "what's new"))
                return HandleWhileAway();

            // ── Fallback ──
            return HandleFallback(trimmed);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing chat message: {Message}", trimmed);
            return new ChatResponsePayload
            {
                Text = $"❌ Error processing command: {ex.Message}",
                Category = ChatResponseCategory.Error,
                SuggestedActions = { new SuggestedAction { Label = "📊 Status", Command = "status" } }
            };
        }
    }

    // ══════════════════════════════════════════
    //  Command Handlers
    // ══════════════════════════════════════════

    private ChatResponsePayload HandleHelp()
    {
        var sb = new StringBuilder();
        sb.AppendLine("🛡️ **WinSentinel Agent — Chat Commands**");
        sb.AppendLine();
        sb.AppendLine("**Status & Info:**");
        sb.AppendLine("  `status` — Agent status, uptime, monitors, score");
        sb.AppendLine("  `monitors` — List active monitoring modules");
        sb.AppendLine("  `threats` — Recent threat events");
        sb.AppendLine("  `today` — Today's activity summary");
        sb.AppendLine("  `history` — Score history and trends");
        sb.AppendLine("  `policy` — Show response policies");
        sb.AppendLine();
        sb.AppendLine("**Scanning & Fixing:**");
        sb.AppendLine("  `scan` — Run full security audit");
        sb.AppendLine("  `scan <module>` — Scan specific module (firewall, network, etc.)");
        sb.AppendLine("  `fix <finding>` — Fix a specific finding");
        sb.AppendLine("  `fix all` — Fix all warnings & critical issues");
        sb.AppendLine();
        sb.AppendLine("**Actions:**");
        sb.AppendLine("  `block <ip>` — Add firewall block rule");
        sb.AppendLine("  `kill <process>` — Terminate a process");
        sb.AppendLine("  `quarantine <file>` — Move file to quarantine");
        sb.AppendLine("  `undo` — Revert last auto-remediation");
        sb.AppendLine("  `ignore <threat>` — Always ignore a threat type");
        sb.AppendLine();
        sb.AppendLine("**Settings:**");
        sb.AppendLine("  `set risk <low|medium|high>` — Change risk tolerance");
        sb.AppendLine("  `pause monitoring` / `resume monitoring`");
        sb.AppendLine("  `export` — Generate a security report");
        sb.AppendLine();
        sb.AppendLine("💡 You can also ask in natural language!");

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Help,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📊 Status", Command = "status" },
                new SuggestedAction { Label = "🔍 Scan", Command = "scan" },
                new SuggestedAction { Label = "⚠️ Threats", Command = "threats" },
                new SuggestedAction { Label = "📈 History", Command = "history" }
            }
        };
    }

    private ChatResponsePayload HandleStatus()
    {
        var snapshot = _state.ToSnapshot();
        var uptime = TimeSpan.FromSeconds(snapshot.UptimeSeconds);
        var uptimeStr = uptime.TotalDays >= 1
            ? $"{(int)uptime.TotalDays}d {uptime.Hours}h {uptime.Minutes}m"
            : uptime.TotalHours >= 1
                ? $"{uptime.Hours}h {uptime.Minutes}m"
                : $"{uptime.Minutes}m {uptime.Seconds}s";

        var sb = new StringBuilder();
        sb.AppendLine("🛡️ **WinSentinel Agent Status**");
        sb.AppendLine();
        sb.AppendLine($"⏱️ Uptime: {uptimeStr}");
        sb.AppendLine($"📡 Active Monitors: {snapshot.ActiveModules.Count} ({string.Join(", ", snapshot.ActiveModules)})");
        sb.AppendLine($"⚠️ Threats Today: {snapshot.ThreatsDetectedToday}");

        if (snapshot.LastScanScore.HasValue)
        {
            var score = snapshot.LastScanScore.Value;
            var grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
            sb.AppendLine($"🛡️ Security Score: {score}/100 (Grade: {grade})");
        }
        else
        {
            sb.AppendLine("🛡️ Security Score: No scan yet");
        }

        if (snapshot.LastScanTime.HasValue)
            sb.AppendLine($"🔍 Last Scan: {snapshot.LastScanTime.Value.ToLocalTime():MMM dd, HH:mm}");
        else
            sb.AppendLine("🔍 Last Scan: Never");

        sb.AppendLine($"🔧 Risk Tolerance: {_config.RiskTolerance}");
        sb.AppendLine($"📋 Version: {snapshot.Version}");

        if (snapshot.IsScanRunning)
            sb.AppendLine("\n⏳ A scan is currently running...");

        var response = new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SecurityScore = snapshot.LastScanScore
        };

        // Add contextual suggestions
        if (!snapshot.LastScanScore.HasValue)
            response.SuggestedActions.Add(new SuggestedAction { Label = "🔍 Run First Scan", Command = "scan" });
        else if (snapshot.LastScanScore < 70)
            response.SuggestedActions.Add(new SuggestedAction { Label = "🔧 Fix All", Command = "fix all" });

        if (snapshot.ThreatsDetectedToday > 0)
            response.SuggestedActions.Add(new SuggestedAction { Label = "⚠️ View Threats", Command = "threats" });

        response.SuggestedActions.Add(new SuggestedAction { Label = "📈 History", Command = "history" });

        return response;
    }

    private ChatResponsePayload HandleMonitors()
    {
        var snapshot = _state.ToSnapshot();
        var sb = new StringBuilder();
        sb.AppendLine("📡 **Active Monitoring Modules**");
        sb.AppendLine();

        if (snapshot.ActiveModules.Count == 0)
        {
            sb.AppendLine("No monitors currently active.");
        }
        else
        {
            foreach (var module in snapshot.ActiveModules)
            {
                var icon = module switch
                {
                    "ProcessMonitor" => "⚙️",
                    "FileSystemMonitor" => "📂",
                    "EventLogMonitor" => "📋",
                    "ScheduledAudit" => "🔍",
                    _ => "🔹"
                };
                sb.AppendLine($"  {icon} {module} — Running");
            }
        }

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SuggestedActions =
            {
                new SuggestedAction { Label = "⏸️ Pause", Command = "pause monitoring" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }

    private ChatResponsePayload HandleThreats()
    {
        var threats = _threatLog.GetRecent(20);
        var sb = new StringBuilder();

        if (threats.Count == 0)
        {
            sb.AppendLine("✅ **No threats detected.** All clear!");
            return new ChatResponsePayload
            {
                Text = sb.ToString(),
                Category = ChatResponseCategory.ThreatList,
                SuggestedActions = { new SuggestedAction { Label = "🔍 Run Scan", Command = "scan" } }
            };
        }

        sb.AppendLine($"⚠️ **Recent Threats** ({threats.Count} events)");
        sb.AppendLine();

        var chatThreats = new List<ChatThreatEvent>();

        foreach (var t in threats.Take(15))
        {
            var icon = t.Severity switch
            {
                ThreatSeverity.Critical => "🔴",
                ThreatSeverity.High => "🟠",
                ThreatSeverity.Medium => "🟡",
                ThreatSeverity.Low => "⚪",
                _ => "ℹ️"
            };

            var time = t.Timestamp.ToLocalTime().ToString("HH:mm:ss");
            sb.AppendLine($"{icon} [{time}] **{t.Title}**");
            sb.AppendLine($"   Source: {t.Source} | {(t.ResponseTaken ?? "No action")}");

            chatThreats.Add(new ChatThreatEvent
            {
                Id = t.Id,
                Timestamp = t.Timestamp,
                Source = t.Source,
                Severity = t.Severity.ToString(),
                Title = t.Title,
                ResponseTaken = t.ResponseTaken
            });
        }

        if (threats.Count > 15)
            sb.AppendLine($"\n... and {threats.Count - 15} more");

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.ThreatList,
            ThreatEvents = chatThreats,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📊 Today's Summary", Command = "today" },
                new SuggestedAction { Label = "↩️ Undo Last", Command = "undo" }
            }
        };
    }

    private ChatResponsePayload HandleTodaySummary()
    {
        var summary = _brain.Journal.GetTodaySummary();
        var sb = new StringBuilder();
        sb.AppendLine(summary.ToString());

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SuggestedActions =
            {
                new SuggestedAction { Label = "⚠️ Threats", Command = "threats" },
                new SuggestedAction { Label = "📈 History", Command = "history" }
            }
        };
    }

    private ChatResponsePayload HandleHistory()
    {
        var sb = new StringBuilder();

        // Get journal entries for trends
        var weekEntries = _brain.Journal.GetThisWeek();
        var weekSummary = _brain.Journal.GetWeekSummary();

        sb.AppendLine("📈 **Security History & Trends**");
        sb.AppendLine();

        // Show last scan score
        if (_state.LastScanScore.HasValue)
        {
            var score = _state.LastScanScore.Value;
            sb.AppendLine($"🛡️ Current Score: {score}/100");
        }

        sb.AppendLine();
        sb.AppendLine($"📊 **This Week:**");
        sb.AppendLine($"  Threats: {weekSummary.ThreatsDetected}");
        sb.AppendLine($"  Actions: {weekSummary.ActionsTaken} (✓{weekSummary.SuccessfulRemediations} ✗{weekSummary.FailedRemediations})");
        sb.AppendLine($"  Correlations: {weekSummary.CorrelationsDetected}");
        sb.AppendLine($"  Severity: 🔴{weekSummary.CriticalCount} 🟠{weekSummary.HighCount} 🟡{weekSummary.MediumCount} ⚪{weekSummary.LowCount}");

        if (weekSummary.TopSources.Count > 0)
        {
            sb.AppendLine($"  Top sources: {string.Join(", ", weekSummary.TopSources.Select(kv => $"{kv.Key}({kv.Value})"))}");
        }

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SecurityScore = _state.LastScanScore,
            SuggestedActions =
            {
                new SuggestedAction { Label = "🔍 Run Scan", Command = "scan" },
                new SuggestedAction { Label = "📊 Today", Command = "today" }
            }
        };
    }

    private async Task<ChatResponsePayload> HandleScanAsync(string? module)
    {
        if (_state.IsScanRunning)
        {
            return SimpleResponse("⏳ A scan is already running. Please wait for it to complete.",
                ChatResponseCategory.General,
                new SuggestedAction { Label = "📊 Status", Command = "status" });
        }

        if (!string.IsNullOrEmpty(module))
        {
            // Single module scan
            var engine = new AuditEngine();
            var result = await engine.RunSingleAuditAsync(module, CancellationToken.None);

            if (result == null)
            {
                return SimpleResponse(
                    $"❌ No audit module found for '{module}'.\n" +
                    "Available: firewall, updates, defender, accounts, network, processes, startup, system, privacy, browser",
                    ChatResponseCategory.Error);
            }

            var score = SecurityScorer.CalculateCategoryScore(result);
            var sb = new StringBuilder();
            sb.AppendLine($"🔍 **{result.ModuleName}** — Score: {score}/100");
            sb.AppendLine();

            foreach (var f in result.Findings.OrderByDescending(f => f.Severity))
            {
                var icon = f.Severity switch
                {
                    Severity.Critical => "🔴",
                    Severity.Warning => "🟡",
                    Severity.Info => "ℹ️",
                    _ => "✅"
                };
                sb.AppendLine($"  {icon} **{f.Title}** — {f.Description}");
                if (f.FixCommand != null)
                    sb.AppendLine($"     🔧 Auto-fix: `fix {f.Title}`");
            }

            var response = new ChatResponsePayload
            {
                Text = sb.ToString(),
                Category = ChatResponseCategory.AuditResult,
                SecurityScore = score
            };

            var fixable = result.Findings.Count(f => f.Severity >= Severity.Warning && f.FixCommand != null);
            if (fixable > 0)
                response.SuggestedActions.Add(new SuggestedAction { Label = $"🔧 Fix {fixable} Issues", Command = "fix all" });

            response.SuggestedActions.Add(new SuggestedAction { Label = "🔍 Full Scan", Command = "scan" });
            return response;
        }

        // Trigger full audit via agent's IPC
        _ = Task.Run(async () =>
        {
            try
            {
                await _ipcServer.TriggerAuditAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error running audit from chat");
            }
        });

        return new ChatResponsePayload
        {
            Text = "🔍 **Full security audit started!**\n\nThis will take a minute. I'll update you when it's done.\nUse `status` to check progress.",
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📊 Status", Command = "status" },
                new SuggestedAction { Label = "⚠️ Threats", Command = "threats" }
            }
        };
    }

    private async Task<ChatResponsePayload> HandleFixAllAsync()
    {
        // Run a quick scan first to find fixable issues
        var engine = new AuditEngine();
        var report = await engine.RunFullAuditAsync(cancellationToken: CancellationToken.None);

        var fixable = report.Results
            .SelectMany(r => r.Findings)
            .Where(f => f.Severity >= Severity.Warning && !string.IsNullOrEmpty(f.FixCommand))
            .ToList();

        if (fixable.Count == 0)
        {
            return SimpleResponse("✅ No fixable issues found. Your system looks good!",
                ChatResponseCategory.ActionConfirmation,
                new SuggestedAction { Label = "📊 Status", Command = "status" });
        }

        var fixEngine = new FixEngine();
        var sb = new StringBuilder();
        sb.AppendLine($"🔧 **Fixing {fixable.Count} issues...**");
        sb.AppendLine();

        int succeeded = 0, failed = 0;
        foreach (var finding in fixable)
        {
            var result = await fixEngine.ExecuteFixAsync(finding);
            if (result.Success)
            {
                sb.AppendLine($"  ✅ {finding.Title}");
                succeeded++;
            }
            else
            {
                sb.AppendLine($"  ❌ {finding.Title}: {result.Error}");
                failed++;
            }
        }

        sb.AppendLine();
        sb.AppendLine($"**Results:** {succeeded} fixed, {failed} failed");

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "🔍 Re-Scan", Command = "scan" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }

    private async Task<ChatResponsePayload> HandleFixAsync(string target)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return SimpleResponse("Usage: `fix <finding>` or `fix all`\nRun `scan` first to see available findings.",
                ChatResponseCategory.General);
        }

        // Run a quick scan to find the finding
        var engine = new AuditEngine();
        var report = await engine.RunFullAuditAsync(cancellationToken: CancellationToken.None);

        var allFindings = report.Results.SelectMany(r => r.Findings).ToList();
        var match = SecurityAdvisor.FindBestMatch(allFindings, target);

        if (match == null)
        {
            return SimpleResponse(
                $"❌ No finding matching \"{target}\" found.\n" +
                "Available findings:\n" +
                string.Join("\n", allFindings
                    .Where(f => f.Severity >= Severity.Warning)
                    .Take(10)
                    .Select(f => $"  • {f.Title}")),
                ChatResponseCategory.Error,
                new SuggestedAction { Label = "🔍 Scan", Command = "scan" });
        }

        if (string.IsNullOrEmpty(match.FixCommand))
        {
            return SimpleResponse(
                $"⚠️ \"{match.Title}\" doesn't have an automated fix.\n" +
                (match.Remediation != null ? $"💡 Manual fix: {match.Remediation}" : ""),
                ChatResponseCategory.General);
        }

        var fixEngine = new FixEngine();
        var result = await fixEngine.ExecuteFixAsync(match);

        if (result.Success)
        {
            return new ChatResponsePayload
            {
                Text = $"✅ **Fixed: {match.Title}**\n{(result.Output != null ? $"Output: {result.Output}" : "")}",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                SuggestedActions =
                {
                    new SuggestedAction { Label = "🔍 Re-Scan", Command = "scan" },
                    new SuggestedAction { Label = "🔧 Fix All", Command = "fix all" }
                }
            };
        }
        else
        {
            return new ChatResponsePayload
            {
                Text = $"❌ **Failed to fix: {match.Title}**\nError: {result.Error}" +
                       (result.RequiredElevation ? "\n💡 Try running WinSentinel as admin." : ""),
                Category = ChatResponseCategory.Error,
                SuggestedActions =
                {
                    new SuggestedAction { Label = "📊 Status", Command = "status" }
                }
            };
        }
    }

    private ChatResponsePayload HandleBlockIp(string ip)
    {
        var record = _brain.Remediator.BlockIp(ip, "Blocked via chat command", "chat-" + Guid.NewGuid().ToString("N")[..8]);

        if (record.Success)
        {
            _brain.Journal.RecordRemediation(record);
            return new ChatResponsePayload
            {
                Text = $"🔥 **Blocked IP: {ip}**\nFirewall rule created to block all inbound traffic from this address.",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                ActionId = record.Id,
                SuggestedActions =
                {
                    new SuggestedAction { Label = "↩️ Undo", Command = "undo" },
                    new SuggestedAction { Label = "📊 Status", Command = "status" }
                }
            };
        }
        else
        {
            return SimpleResponse($"❌ Failed to block {ip}: {record.ErrorMessage}\n💡 Running as admin may be required.",
                ChatResponseCategory.Error);
        }
    }

    private ChatResponsePayload HandleKillProcess(string processInput)
    {
        // Try to parse as PID first
        if (int.TryParse(processInput, out var pid))
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                var name = proc.ProcessName;
                var record = _brain.Remediator.KillProcess(pid, name, "chat-" + Guid.NewGuid().ToString("N")[..8]);
                _brain.Journal.RecordRemediation(record);

                return record.Success
                    ? new ChatResponsePayload
                    {
                        Text = $"⚙️ **Killed process: {name} (PID {pid})**",
                        Category = ChatResponseCategory.ActionConfirmation,
                        ActionPerformed = true,
                        ActionId = record.Id
                    }
                    : SimpleResponse($"❌ Failed to kill PID {pid}: {record.ErrorMessage}", ChatResponseCategory.Error);
            }
            catch
            {
                return SimpleResponse($"❌ Process with PID {pid} not found.", ChatResponseCategory.Error);
            }
        }

        // Try by name
        var processes = Process.GetProcessesByName(processInput.Replace(".exe", ""));
        if (processes.Length == 0)
        {
            return SimpleResponse($"❌ No process named '{processInput}' found.", ChatResponseCategory.Error);
        }

        if (processes.Length > 1)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"⚠️ Found {processes.Length} processes named '{processInput}':");
            foreach (var p in processes.Take(10))
            {
                sb.AppendLine($"  PID {p.Id} — {p.ProcessName}");
            }
            sb.AppendLine("\nSpecify a PID: `kill <pid>`");
            foreach (var p in processes) p.Dispose();
            return SimpleResponse(sb.ToString(), ChatResponseCategory.General);
        }

        var target = processes[0];
        var killRecord = _brain.Remediator.KillProcess(target.Id, target.ProcessName,
            "chat-" + Guid.NewGuid().ToString("N")[..8]);
        _brain.Journal.RecordRemediation(killRecord);
        target.Dispose();

        return killRecord.Success
            ? new ChatResponsePayload
            {
                Text = $"⚙️ **Killed process: {processInput} (PID {target.Id})**",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                ActionId = killRecord.Id
            }
            : SimpleResponse($"❌ Failed to kill '{processInput}': {killRecord.ErrorMessage}", ChatResponseCategory.Error);
    }

    private ChatResponsePayload HandleQuarantineFile(string filePath)
    {
        if (!System.IO.File.Exists(filePath))
        {
            return SimpleResponse($"❌ File not found: {filePath}", ChatResponseCategory.Error);
        }

        var record = _brain.Remediator.QuarantineFile(filePath,
            "chat-" + Guid.NewGuid().ToString("N")[..8]);
        _brain.Journal.RecordRemediation(record);

        return record.Success
            ? new ChatResponsePayload
            {
                Text = $"🗄️ **Quarantined: {Path.GetFileName(filePath)}**\nMoved to quarantine folder.",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                ActionId = record.Id,
                SuggestedActions =
                {
                    new SuggestedAction { Label = "↩️ Undo", Command = "undo" }
                }
            }
            : SimpleResponse($"❌ Failed to quarantine: {record.ErrorMessage}", ChatResponseCategory.Error);
    }

    private ChatResponsePayload HandleUndoLast()
    {
        var history = _brain.Remediator.GetRecent(1);
        if (history.Count == 0)
        {
            return SimpleResponse("❌ No recent actions to undo.", ChatResponseCategory.General);
        }

        var last = history[0];
        if (last.Undone)
        {
            return SimpleResponse($"↩️ Last action was already undone: {last.Description}", ChatResponseCategory.General);
        }

        var undoResult = _brain.UndoRemediation(last.Id);

        return undoResult.Success
            ? new ChatResponsePayload
            {
                Text = $"↩️ **Undone:** {undoResult.Description}",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                SuggestedActions =
                {
                    new SuggestedAction { Label = "📊 Status", Command = "status" }
                }
            }
            : SimpleResponse($"❌ Undo failed: {undoResult.ErrorMessage}", ChatResponseCategory.Error);
    }

    private ChatResponsePayload HandleIgnore(string threatType)
    {
        _brain.Policy.AddUserOverride(threatType, UserOverrideAction.AlwaysIgnore);

        return new ChatResponsePayload
        {
            Text = $"🔕 **Ignoring:** \"{threatType}\"\nThis threat type will be suppressed in future detections.\nUse `policy` to review all overrides.",
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📋 Policies", Command = "policy" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }

    private ChatResponsePayload HandleShowPolicies()
    {
        var policy = _brain.Policy;
        var sb = new StringBuilder();
        sb.AppendLine("📋 **Response Policies**");
        sb.AppendLine();
        sb.AppendLine($"🎯 Risk Tolerance: **{policy.RiskTolerance}**");
        sb.AppendLine();

        if (policy.Rules.Count > 0)
        {
            sb.AppendLine($"**Custom Rules ({policy.Rules.Count}):**");
            foreach (var rule in policy.Rules.Take(10))
            {
                sb.AppendLine($"  • {rule.TitlePattern ?? rule.Category?.ToString() ?? "All"} → {rule.Action} (priority {rule.Priority})");
            }
            sb.AppendLine();
        }

        if (policy.UserOverrides.Count > 0)
        {
            sb.AppendLine($"**User Overrides ({policy.UserOverrides.Count}):**");
            foreach (var ov in policy.UserOverrides)
            {
                sb.AppendLine($"  • \"{ov.ThreatTitle}\" → {ov.OverrideAction}");
            }
        }
        else
        {
            sb.AppendLine("No user overrides set.");
        }

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SuggestedActions =
            {
                new SuggestedAction { Label = "🎯 Set Risk Low", Command = "set risk low" },
                new SuggestedAction { Label = "🎯 Set Risk Medium", Command = "set risk medium" },
                new SuggestedAction { Label = "🎯 Set Risk High", Command = "set risk high" }
            }
        };
    }

    private ChatResponsePayload HandleSetRisk(string level)
    {
        if (!Enum.TryParse<RiskTolerance>(level, true, out var riskLevel))
        {
            return SimpleResponse("❌ Invalid risk level. Use: `set risk low`, `set risk medium`, or `set risk high`",
                ChatResponseCategory.Error);
        }

        _config.RiskTolerance = riskLevel;
        _config.Save();
        _brain.Policy.RiskTolerance = riskLevel;
        _brain.Policy.Save();

        var description = riskLevel switch
        {
            RiskTolerance.Low => "Aggressive — scan frequently, alert on everything, auto-fix critical",
            RiskTolerance.Medium => "Balanced — standard intervals, alert on critical+high",
            RiskTolerance.High => "Relaxed — scan less often, only alert on critical",
            _ => ""
        };

        return new ChatResponsePayload
        {
            Text = $"🎯 **Risk tolerance set to: {riskLevel}**\n{description}",
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📋 Policies", Command = "policy" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }

    private ChatResponsePayload HandlePauseMonitoring()
    {
        var activeModules = _state.ActiveModules.Where(kv => kv.Value).Select(kv => kv.Key).ToList();

        // We can't actually stop modules without injecting them, but we can toggle config
        foreach (var module in activeModules)
        {
            _config.ModuleToggles[module] = false;
        }
        _config.Save();

        return new ChatResponsePayload
        {
            Text = $"⏸️ **Monitoring paused.**\n{activeModules.Count} modules flagged to pause.\nNote: Full pause takes effect after agent restart. Modules will stop accepting new events.",
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "▶️ Resume", Command = "resume monitoring" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }

    private ChatResponsePayload HandleResumeMonitoring()
    {
        var toggledOff = _config.ModuleToggles.Where(kv => !kv.Value).Select(kv => kv.Key).ToList();

        foreach (var module in toggledOff)
        {
            _config.ModuleToggles[module] = true;
        }
        _config.Save();

        return new ChatResponsePayload
        {
            Text = $"▶️ **Monitoring resumed.**\n{toggledOff.Count} modules re-enabled.",
            Category = ChatResponseCategory.ActionConfirmation,
            ActionPerformed = true,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📡 Monitors", Command = "monitors" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }

    private async Task<ChatResponsePayload> HandleExportAsync()
    {
        try
        {
            var engine = new AuditEngine();
            var report = await engine.RunFullAuditAsync(cancellationToken: CancellationToken.None);
            var generator = new ReportGenerator();

            var dataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinSentinel");
            Directory.CreateDirectory(dataDir);
            var reportPath = Path.Combine(dataDir, $"WinSentinel-Report-{DateTime.Now:yyyyMMdd-HHmmss}.html");

            var html = generator.GenerateHtmlReport(report);
            await System.IO.File.WriteAllTextAsync(reportPath, html);

            return new ChatResponsePayload
            {
                Text = $"📄 **Report generated!**\nSaved to: `{reportPath}`\nScore: {report.SecurityScore}/100",
                Category = ChatResponseCategory.ActionConfirmation,
                ActionPerformed = true,
                SecurityScore = report.SecurityScore,
                SuggestedActions =
                {
                    new SuggestedAction { Label = "📊 Status", Command = "status" }
                }
            };
        }
        catch (Exception ex)
        {
            return SimpleResponse($"❌ Report generation failed: {ex.Message}", ChatResponseCategory.Error);
        }
    }

    // ── Natural Language Handlers ──

    private ChatResponsePayload HandleSuspiciousToday()
    {
        var todayThreats = _threatLog.GetToday()
            .Where(t => t.Severity >= ThreatSeverity.Medium)
            .ToList();

        if (todayThreats.Count == 0)
        {
            return SimpleResponse("✅ Nothing suspicious today. All monitors report normal activity.",
                ChatResponseCategory.Status,
                new SuggestedAction { Label = "🔍 Run Scan", Command = "scan" });
        }

        var sb = new StringBuilder();
        sb.AppendLine($"⚠️ **{todayThreats.Count} suspicious event(s) today:**");
        sb.AppendLine();

        var chatThreats = new List<ChatThreatEvent>();
        foreach (var t in todayThreats.Take(10))
        {
            var icon = t.Severity switch
            {
                ThreatSeverity.Critical => "🔴",
                ThreatSeverity.High => "🟠",
                _ => "🟡"
            };
            sb.AppendLine($"{icon} **{t.Title}** ({t.Source})");
            sb.AppendLine($"   {t.Description}");

            chatThreats.Add(new ChatThreatEvent
            {
                Id = t.Id,
                Timestamp = t.Timestamp,
                Source = t.Source,
                Severity = t.Severity.ToString(),
                Title = t.Title,
                ResponseTaken = t.ResponseTaken
            });
        }

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.ThreatList,
            ThreatEvents = chatThreats,
            SuggestedActions =
            {
                new SuggestedAction { Label = "📊 Summary", Command = "today" },
                new SuggestedAction { Label = "↩️ Undo Last", Command = "undo" }
            }
        };
    }

    private ChatResponsePayload HandleExplainAction(string input)
    {
        var recentActions = _brain.Journal.Query(new JournalQuery
        {
            EntryType = JournalEntryType.ActionTaken,
            Limit = 5
        });

        if (recentActions.Count == 0)
        {
            return SimpleResponse("No recent actions found in the journal.", ChatResponseCategory.General);
        }

        var sb = new StringBuilder();
        sb.AppendLine("📝 **Recent Agent Actions:**");
        sb.AppendLine();

        foreach (var entry in recentActions)
        {
            sb.AppendLine($"⏱️ {entry.Timestamp.ToLocalTime():MMM dd HH:mm}");
            sb.AppendLine($"  {entry.Summary}");
            if (entry.Details != null)
                sb.AppendLine($"  📋 {entry.Details}");
            if (entry.PolicyDecision != null)
                sb.AppendLine($"  🧠 Decision: {entry.PolicyDecision}");
            sb.AppendLine();
        }

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.General,
            SuggestedActions =
            {
                new SuggestedAction { Label = "↩️ Undo Last", Command = "undo" },
                new SuggestedAction { Label = "📊 Today", Command = "today" }
            }
        };
    }

    private ChatResponsePayload HandleWhileAway()
    {
        // Get journal entries from the last 24 hours
        var recent = _brain.Journal.Query(new JournalQuery
        {
            After = DateTimeOffset.UtcNow.AddHours(-24),
            Limit = 30
        });

        if (recent.Count == 0)
        {
            return SimpleResponse("Nothing happened while you were away. All quiet! 😴",
                ChatResponseCategory.Status);
        }

        var sb = new StringBuilder();
        sb.AppendLine($"📋 **Activity in the last 24 hours** ({recent.Count} events):");
        sb.AppendLine();

        var threats = recent.Where(e => e.EntryType == JournalEntryType.ThreatDetected).ToList();
        var actions = recent.Where(e => e.EntryType == JournalEntryType.ActionTaken).ToList();
        var correlations = recent.Where(e => e.EntryType == JournalEntryType.CorrelationDetected).ToList();

        if (threats.Count > 0)
        {
            sb.AppendLine($"⚠️ **{threats.Count} threats detected:**");
            foreach (var t in threats.Take(5))
                sb.AppendLine($"  • {t.Summary}");
            if (threats.Count > 5)
                sb.AppendLine($"  ... and {threats.Count - 5} more");
            sb.AppendLine();
        }

        if (actions.Count > 0)
        {
            sb.AppendLine($"🔧 **{actions.Count} actions taken:**");
            foreach (var a in actions.Take(5))
                sb.AppendLine($"  • {a.Summary}");
            sb.AppendLine();
        }

        if (correlations.Count > 0)
        {
            sb.AppendLine($"🔗 **{correlations.Count} correlations detected:**");
            foreach (var c in correlations.Take(3))
                sb.AppendLine($"  • {c.Summary}");
            sb.AppendLine();
        }

        return new ChatResponsePayload
        {
            Text = sb.ToString(),
            Category = ChatResponseCategory.Status,
            SuggestedActions =
            {
                new SuggestedAction { Label = "⚠️ Threats", Command = "threats" },
                new SuggestedAction { Label = "📊 Status", Command = "status" }
            }
        };
    }

    private ChatResponsePayload HandleFallback(string input)
    {
        return new ChatResponsePayload
        {
            Text = $"🤔 I'm not sure how to handle \"{input}\".\n\n" +
                   "Try:\n" +
                   "  • `status` — Check agent status\n" +
                   "  • `scan` — Run a security audit\n" +
                   "  • `threats` — View recent threats\n" +
                   "  • `help` — See all commands\n\n" +
                   "💡 Or ask in natural language: \"What's my security score?\", \"Anything suspicious today?\"",
            Category = ChatResponseCategory.Help,
            SuggestedActions =
            {
                new SuggestedAction { Label = "❓ Help", Command = "help" },
                new SuggestedAction { Label = "📊 Status", Command = "status" },
                new SuggestedAction { Label = "🔍 Scan", Command = "scan" }
            }
        };
    }

    // ══════════════════════════════════════════
    //  Utility Helpers
    // ══════════════════════════════════════════

    private static ChatResponsePayload SimpleResponse(string text, ChatResponseCategory category,
        params SuggestedAction[] actions)
    {
        var response = new ChatResponsePayload { Text = text, Category = category };
        foreach (var action in actions)
            response.SuggestedActions.Add(action);
        return response;
    }

    private static bool MatchesAny(string input, params string[] patterns) =>
        patterns.Any(p => input.Contains(p, StringComparison.OrdinalIgnoreCase));

    private static string? ExtractIp(string text)
    {
        var match = Regex.Match(text, @"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b");
        return match.Success ? match.Groups[1].Value : null;
    }
}

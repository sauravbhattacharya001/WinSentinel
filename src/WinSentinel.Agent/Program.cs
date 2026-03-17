using Serilog;
using Serilog.Events;
using WinSentinel.Agent;
using WinSentinel.Agent.Modules;
using WinSentinel.Agent.Services;
using WinSentinel.Core.Services;

var logPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "WinSentinel", "logs", "agent-.log");

// Bootstrap logger for startup errors (before DI is available)
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .WriteTo.Console(outputTemplate:
        "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}")
    .WriteTo.File(logPath,
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14,
        outputTemplate:
            "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}")
    .CreateBootstrapLogger();

try
{
    var builder = Host.CreateDefaultBuilder(args);

    builder.UseSerilog((context, services, loggerConfig) =>
    {
        var config = services.GetRequiredService<AgentConfig>();
        loggerConfig
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .Enrich.With(new AgentEnricher(config))
            .WriteTo.Console(outputTemplate:
                "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}")
            .WriteTo.File(logPath,
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 14,
                outputTemplate:
                    "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}");
    });

    // Enable Windows Service support (no-op when running as console)
    builder.UseWindowsService(options =>
    {
        options.ServiceName = "WinSentinel Agent";
    });

builder.ConfigureServices((context, services) =>
{
    // Core agent services
    services.AddSingleton<AgentState>();
    services.AddSingleton<AgentConfig>();
    services.AddSingleton<ThreatLog>();

    // IPC server for UI communication
    services.AddSingleton<IpcServer>();
    services.AddSingleton<FixEngine>();
    services.AddHostedService(sp => sp.GetRequiredService<IpcServer>());

    // Agent Brain components (Step 5)
    services.AddSingleton<ResponsePolicy>(sp =>
    {
        var config = sp.GetRequiredService<AgentConfig>();
        var policy = ResponsePolicy.CreateDefault(config.RiskTolerance);
        policy.Load();
        return policy;
    });
    services.AddSingleton<ThreatCorrelator>();
    services.AddSingleton<AutoRemediator>();
    services.AddSingleton<AgentJournal>();
    services.AddSingleton<AgentBrain>();
    services.AddSingleton<ChatHandler>();

    // Agent modules
    services.AddSingleton<IAgentModule, ScheduledAuditModule>();
    services.AddSingleton<IAgentModule, ProcessMonitorModule>();
    services.AddSingleton<IAgentModule, FileSystemMonitorModule>();
    services.AddSingleton<IAgentModule, EventLogMonitorModule>();
    services.AddSingleton<IAgentModule, NetworkMonitorModule>();
    services.AddSingleton<IAgentModule, ClipboardMonitorModule>();

    // Main orchestrator
    services.AddHostedService<AgentService>();
});

    var host = builder.Build();

    // Initialize config
    var config = host.Services.GetRequiredService<AgentConfig>();
    config.Load();

    Log.Information("WinSentinel Agent starting (RiskTolerance={RiskTolerance})", config.RiskTolerance);
    await host.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "WinSentinel Agent terminated unexpectedly");
}
finally
{
    await Log.CloseAndFlushAsync();
}

using WinSentinel.Agent;
using WinSentinel.Agent.Modules;
using WinSentinel.Agent.Services;

var builder = Host.CreateDefaultBuilder(args);

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
    services.AddHostedService(sp => sp.GetRequiredService<IpcServer>());

    // Agent modules
    services.AddSingleton<IAgentModule, ScheduledAuditModule>();
    services.AddSingleton<IAgentModule, ProcessMonitorModule>();
    services.AddSingleton<IAgentModule, FileSystemMonitorModule>();
    services.AddSingleton<IAgentModule, EventLogMonitorModule>();

    // Main orchestrator
    services.AddHostedService<AgentService>();
});

var host = builder.Build();

// Initialize config
var config = host.Services.GetRequiredService<AgentConfig>();
config.Load();

await host.RunAsync();

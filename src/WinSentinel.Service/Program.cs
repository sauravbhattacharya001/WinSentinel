using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WinSentinel.Service;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "WinSentinel Security Monitor";
});

builder.Services.AddHostedService<SecurityMonitorWorker>();

var host = builder.Build();
host.Run();

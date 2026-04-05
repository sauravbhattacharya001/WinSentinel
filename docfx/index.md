# WinSentinel Documentation

Welcome to the **WinSentinel** documentation - your always-on Windows security agent.

## What is WinSentinel?

WinSentinel is a Windows-native security agent that monitors, audits, and remediates security issues on your machine. It features:

- **13 audit modules** covering Windows Defender, firewall, network, updates, privacy, and more
- **Real-time monitoring** with file integrity and event log watchers
- **AI-powered threat correlation** that connects disparate events into threat narratives
- **Auto-remediation** with PowerShell-based fix scripts
- **Chat control plane** for natural-language interaction
- **Compliance profiles** (CIS, HIPAA, PCI-DSS, SOC2, custom)
- **Security scoring** (0-100 with A-F grades)

## Quick Links

- [Getting Started](articles/getting-started.md) - Install and run your first audit
- [Configuration](articles/configuration.md) - All settings, environment variables, and service setup
- [Architecture](articles/architecture.md) - How WinSentinel is built
- [CLI Reference](articles/cli-reference.md) - Command-line usage
- [Compliance Profiles](articles/compliance-profiles.md) - Home, Developer, Enterprise, and Server profiles
- [Extending](articles/extending.md) - Add custom audit modules
- [Security Hardening](articles/security-hardening.md) - Production deployment best practices
- [API Reference](api/index.md) - Full .NET API documentation
- [GitHub Repository](https://github.com/sauravbhattacharya001/WinSentinel)

## Project Structure

| Project | Description |
|---------|-------------|
| `WinSentinel.Core` | Audit modules, scoring engine, threat correlation, compliance profiles |
| `WinSentinel.Cli` | Command-line interface for running audits and managing the agent |
| `WinSentinel.Agent` | Background agent with file watchers, event monitors, and scheduling |
| `WinSentinel.App` | WPF desktop application with chat interface |
| `WinSentinel.Service` | Windows Service host for always-on operation |

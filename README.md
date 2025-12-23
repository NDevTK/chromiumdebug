# Chromium Security Research WinDbg Toolkit

A WinDbg debugging toolkit for Chromium security researchers.

## Quick Start

```batch
debug_chrome.bat
```

Then in WinDbg: `!chelp`

## Commands

### Process Info
| Command | Description |
|---------|-------------|
| `!chelp` | Show all commands |
| `!procs` | List all Chrome processes with types & sites |
| `!proc` | Show current process type (+ site if renderer) |
| `!cmdline` | Show command line switches |
| `!frames` | List all frames in current renderer process |

### Sandbox & Security
| Command | Description |
|---------|-------------|
| `!sandbox_state` | Check sandbox status of current process |
| `!sandbox_all` | Dashboard of all process sandbox states |
| `!sandbox_token` | Dump token info and integrity level |

### Security Breakpoints
| Command | Description |
|---------|-------------|
| `!bp_bad` | **Break on security violations (mojo::ReportBadMessage)** |
| `!bp_security` | Break on ChildProcessSecurityPolicy checks |
| `!bp_renderer` | Break when renderers are launched |
| `!bp_sandbox` | Break when sandbox lowers token |
| `!bp_mojo` | Break on Mojo interface binding |
| `!bp_ipc` | Break on IPC message dispatch |
| `!trace_ipc` | Enable IPC message logging |

### Vulnerability Hunting
| Command | Description |
|---------|-------------|
| `!vuln_hunt` | **Set UAF, type confusion, race condition breakpoints** |
| `!heap_info` | PartitionAlloc/V8 heap inspection guide |

### Origin Spoofing & Function Patching
| Command | Description |
|---------|-------------|
| `!spoof "url"` | Spoof renderer origin by patching memory (auto-detects current) |
| `!patch "name" "value"` | Patch function to return specific value (auto-searches symbols) |

### Cross-Process Execution
| Command | Description |
|---------|-------------|
| `!run_renderer "cmd"` | Run command in all renderer processes |
| `!run_browser "cmd"` | Run command in browser process |
| `!run_gpu "cmd"` | Run command in GPU process |
| `!script_renderer "path"` | Load script in all renderers |
| `!on_attach "cmd"` | Auto-run command when renderers attach |
| `!script_attach "path"` | Auto-load script when renderers attach |

## Files

```
ChromeHelper/
├── debug_chrome.bat          # Launcher (auto-cleans old sessions)
├── chromium_security.js      # Main WinDbg script (includes all hooks)
└── init.txt                  # WinDbg init commands
```

## Symbol Configuration

The batch script auto-configures symbols. Manual setup:
```
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.sympath+ srv*C:\Symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com
.reload /f
```

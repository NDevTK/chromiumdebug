/// =============================================================================
/// Chromium Security Research WinDbg Script
/// =============================================================================
/// A comprehensive debugging toolkit for Chromium security research.
/// Load this script with: .scriptload chromium_security.js
/// =============================================================================

"use strict";

/// Global state
var g_initialized = false;
var g_processTypes = {};

/// =============================================================================
/// INITIALIZATION
/// =============================================================================

function initializeScript() {
    return [
        new host.apiVersionSupport(1, 7),
        // Process info
        new host.functionAlias(chrome_process_type, "proc"),
        new host.functionAlias(chrome_cmdline, "cmdline"),
        new host.functionAlias(chrome_processes, "procs"),
        new host.functionAlias(renderer_frames, "frames"),
        // Sandbox
        new host.functionAlias(sandbox_state, "sandbox_state"),
        new host.functionAlias(sandbox_status_all, "sandbox_all"),
        new host.functionAlias(sandbox_token, "sandbox_token"),
        // Breakpoints
        new host.functionAlias(bp_renderer_launch, "bp_renderer"),
        new host.functionAlias(bp_sandbox_lower, "bp_sandbox"),
        new host.functionAlias(bp_mojo_interface, "bp_mojo"),
        new host.functionAlias(bp_ipc_message, "bp_ipc"),
        new host.functionAlias(bp_bad_message, "bp_bad"),
        new host.functionAlias(bp_security_check, "bp_security"),
        new host.functionAlias(trace_ipc, "trace_ipc"),
        // Vuln hunting
        new host.functionAlias(vuln_hunt, "vuln_hunt"),
        new host.functionAlias(heap_info, "heap_info"),
        // Spoofing & patching
        new host.functionAlias(patch_function, "patch"),
        new host.functionAlias(spoof_origin, "spoof"),
        // Cross-process execution
        new host.functionAlias(run_in_renderer, "run_renderer"),
        new host.functionAlias(run_in_browser, "run_browser"),
        new host.functionAlias(run_in_gpu, "run_gpu"),
        new host.functionAlias(run_script_in_renderer, "script_renderer"),
        new host.functionAlias(on_renderer_attach, "on_attach"),
        new host.functionAlias(script_in_renderer_attach, "script_attach"),
        // Help
        new host.functionAlias(help, "chelp"),
        // Blink Hooks
        new host.functionAlias(blink_help, "blink_help"),
        new host.functionAlias(bp_element, "bp_element"),
        new host.functionAlias(bp_nav, "bp_nav"),
        new host.functionAlias(bp_pm, "bp_pm"),
        new host.functionAlias(bp_fetch, "bp_fetch"),
        // V8 Hooks
        new host.functionAlias(v8_help, "v8_help"),
        new host.functionAlias(bp_compile, "bp_compile"),
        new host.functionAlias(bp_gc, "bp_gc"),
        new host.functionAlias(bp_wasm, "bp_wasm"),
        new host.functionAlias(bp_jit, "bp_jit"),
        // V8 Pointer Compression
        new host.functionAlias(v8_cage_info, "v8_cage"),
        new host.functionAlias(decompress, "decompress"),
        new host.functionAlias(decompress_gc, "decompress_gc")
    ];
}

/// Initialize the Chrome debugging environment
function chrome_init() {
    host.diagnostics.debugLog("=============================================================================\n");
    host.diagnostics.debugLog("  Chromium Security Research Debugger - Initialized\n");
    host.diagnostics.debugLog("=============================================================================\n");
    host.diagnostics.debugLog("  Type !chelp for available commands\n");
    host.diagnostics.debugLog("=============================================================================\n\n");

    g_initialized = true;

    // Set up useful aliases
    try {
        var ctl = host.namespace.Debugger.Utility.Control;
        ctl.ExecuteCommand(".prefer_dml 1");
    } catch (e) {
        // Ignore if fails
    }

    return "Chromium debugger initialized. Use !chelp for commands.";
}

/// =============================================================================
/// HELP
/// =============================================================================

function help() {
    var helpText = `
=============================================================================
  Chromium Security Research Debugger - Commands
=============================================================================

  PROCESS IDENTIFICATION:
    !proc                 - Show process type (+ site if renderer)
    !cmdline              - Show the command line for the current process
    !procs                - List all Chrome processes with types
    !frames               - List all frames in current renderer process

  SANDBOX & SECURITY:
    !sandbox_all          - Dashboard of sandbox status for ALL processes
    !sandbox_state        - Check sandbox status of CURRENT process
    !sandbox_token        - Dump process token info and integrity level

  SECURITY BREAKPOINTS:
    !bp_renderer          - Break when renderer processes are launched
    !bp_sandbox           - Break when sandbox lowers token
    !bp_mojo              - Break on Mojo interface binding
    !bp_ipc               - Break on IPC message dispatch
    !bp_bad               - Break on mojo::ReportBadMessage (security violations!)
    !bp_security          - Break on ChildProcessSecurityPolicy checks
    !trace_ipc            - Enable IPC message logging (noisy)

  VULNERABILITY HUNTING:
    !vuln_hunt            - UAF, type confusion, race condition breakpoints
    !heap_info            - PartitionAlloc/V8 heap inspection guide

  ORIGIN SPOOFING & FUNCTION PATCHING (renderer only):
    !spoof(\"url\")                       - Spoof origin by patching memory
    !patch(\"FullscreenIsSupported\",\"false\") - Patch function (auto-inlining detection)


  BLINK DOM HOOKS:
    !blink_help           - Show full Blink DOM help
    !bp_element           - Break on DOM element creation
    !bp_nav               - Break on navigation
    !bp_pm                - Break on postMessage
    !bp_fetch             - Break on Fetch/XHR

  V8 EXPLOITATION HOOKS:
    !v8_help              - Show full V8 help
    !bp_compile           - Break on script compilation
    !bp_gc                - Break on Garbage Collection
    !bp_wasm              - Break on WebAssembly
    !bp_jit               - Break on JIT compilation

  V8 POINTER COMPRESSION:
    !v8_cage              - Show V8 cage base address
    !decompress(ptr)      - Decompress a 32-bit V8 compressed pointer

  PROCESS-SPECIFIC EXECUTION (works from any process):
    !run_renderer("cmd")      - Run command in all renderer processes
    !run_browser("cmd")       - Run command in browser process
    !run_gpu("cmd")           - Run command in GPU process
    !script_renderer("path")  - Load script in all renderers
    !on_attach("cmd")         - Auto-run command when renderers attach
    !script_attach("path")    - Auto-load script when renderers attach

  TIPS:
    - Use '|' to switch between processes: |0s, |1s, etc.
    - Use '||' to list all debugged processes
    - Use '~*k' to get stacks from all threads
    
=============================================================================
`;
    host.diagnostics.debugLog(helpText);
    return "";
}

/// =============================================================================
/// INTERNAL HELPERS
/// =============================================================================

/// Cache for V8 cage base address
var g_v8CageBase = null;

/// Get V8 pointer compression cage base address
/// V8 uses pointer compression where 64-bit pointers are stored as 32-bit offsets
/// from a cage base address. This function finds that base.
function getV8CageBase() {
    if (g_v8CageBase !== null) {
        return g_v8CageBase;
    }

    var ctl = host.namespace.Debugger.Utility.Control;

    try {
        // Try to find v8::internal::MainCage::base_
        var xOutput = ctl.ExecuteCommand("x chrome!v8::internal::MainCage::base_");
        for (var line of xOutput) {
            var match = line.toString().match(/^([0-9a-fA-F`]+)/);
            if (match) {
                var addr = match[1].replace(/`/g, "");
                // Read the value at this address (it's a uintptr_t)
                var dqOutput = ctl.ExecuteCommand("dq 0x" + addr + " L1");
                for (var dline of dqOutput) {
                    var dMatch = dline.toString().match(/[0-9a-fA-F`]+\s+([0-9a-fA-F`]+)/);
                    if (dMatch) {
                        g_v8CageBase = dMatch[1].replace(/`/g, "");
                        return g_v8CageBase;
                    }
                }
            }
        }
    } catch (e) { }

    return null;
}

/// Decompress a V8 compressed pointer
/// Input: 32-bit compressed pointer value (as hex string or number)
/// Returns: Full 64-bit pointer (as hex string)
function decompressV8Ptr(compressedPtr) {
    var cageBase = getV8CageBase();
    if (!cageBase) {
        return null;
    }

    // Convert to BigInt for proper 64-bit math
    var base = BigInt("0x" + cageBase);
    var compressed;

    if (typeof compressedPtr === "string") {
        compressed = BigInt(compressedPtr.startsWith("0x") ? compressedPtr : "0x" + compressedPtr);
    } else {
        compressed = BigInt(compressedPtr);
    }

    // Sign-extend the 32-bit value if needed (V8 uses signed offsets)
    if (compressed > 0x7FFFFFFF) {
        compressed = compressed - BigInt("0x100000000");
    }

    var fullPtr = base + compressed;
    return fullPtr.toString(16);
}

/// Cache for cppgc/Oilpan cage base address
var g_cppgcCageBase = null;

/// Get cppgc/Oilpan pointer compression cage base address
/// Oilpan uses its own compression scheme separate from V8
function getCppgcCageBase() {
    if (g_cppgcCageBase !== null) {
        return g_cppgcCageBase;
    }

    var ctl = host.namespace.Debugger.Utility.Control;

    try {
        // Try to find cppgc::internal::CageBaseGlobal::g_base_
        var xOutput = ctl.ExecuteCommand("x chrome!cppgc::internal::CageBaseGlobal::g_base_");
        for (var line of xOutput) {
            var match = line.toString().match(/^([0-9a-fA-F`]+)/);
            if (match) {
                var addr = match[1].replace(/`/g, "");
                // Read the value at this address (it's a uintptr_t in a union)
                var dqOutput = ctl.ExecuteCommand("dq 0x" + addr + " L1");
                for (var dline of dqOutput) {
                    var dMatch = dline.toString().match(/[0-9a-fA-F`]+\s+([0-9a-fA-F`]+)/);
                    if (dMatch) {
                        g_cppgcCageBase = dMatch[1].replace(/`/g, "");
                        return g_cppgcCageBase;
                    }
                }
            }
        }
    } catch (e) { }

    return null;
}

/// Decompress a cppgc/Oilpan compressed pointer
/// Formula: decompressed = (sign_extend_32(compressed) << 1) & base
/// contextAddr: Optional address of an object in the same heap (to derive base)
function decompressCppgcPtr(compressedPtr, contextAddr) {
    // shift = 3 (Larger Cage)
    const kPointerCompressionShift = 3n;
    // 16GB cage -> 34 bits of offset. Mask is 2^34 - 1.
    const kPointerCompressionMask = 0x3FFFFFFFFn;

    let base;

    // Strategy 1: Use context address if provided (most reliable for specific objects)
    if (contextAddr) {
        var context = BigInt(contextAddr.toString().startsWith("0x") ? contextAddr : "0x" + contextAddr);

        // Derive base from context address for 16GB cage (shift=3)
        // 1. Get the page base by clearing the lower 34 bits (preserves the high bits that identify the 16GB cage)
        //    Since we can't use ~ BigInt easily in JS bitwise operations safely with mixed signs sometimes, 
        //    we construct the mask manually.
        //    ~0x3FFFFFFFF is ...FFFFFC00000000
        const invMask = BigInt("0xFFFFFFFC00000000");
        const cageBaseAddr = context & invMask;

        // 2. Create the "mask-like" base by ORing with the compression mask
        //    (CageBaseGlobal::g_base_ stores it this way: base_addr | mask)
        base = cageBaseAddr | kPointerCompressionMask;
    }
    // Strategy 2: Fallback to global cage base
    else {
        var cageBase = getCppgcCageBase();
        if (!cageBase) {
            return null; // Cannot decompress without a base
        }
        base = BigInt("0x" + cageBase);
    }

    var compressed;
    if (typeof compressedPtr === "string") {
        var ptrStr = compressedPtr.replace(/`/g, "");
        compressed = BigInt(ptrStr.startsWith("0x") ? ptrStr : "0x" + ptrStr);
    } else if (typeof compressedPtr === "number") {
        // WinDbg passes hex values as numbers - convert to hex string first
        compressed = BigInt("0x" + compressedPtr.toString(16));
    } else {
        compressed = BigInt(compressedPtr);
    }

    // Sign-extend the 32-bit value to 64-bit
    // The high bit (bit 31) indicates if we need sign extension
    var signExtended;
    if (compressed >= BigInt("0x80000000")) {
        // Negative - sign extend with 1s in upper 32 bits
        signExtended = BigInt("0xFFFFFFFF00000000") | compressed;
    } else {
        signExtended = compressed;
    }

    // Shift left by kPointerCompressionShift
    var shifted = signExtended << kPointerCompressionShift;

    // Mask to 64 bits (BigInt can be arbitrary size)
    shifted = shifted & BigInt("0xFFFFFFFFFFFFFFFF");

    // AND with base
    var fullPtr = shifted & base;

    return fullPtr.toString(16);
}

/// Display cage base info for both V8 and cppgc/Oilpan
function v8_cage_info() {
    host.diagnostics.debugLog("\n=== Pointer Compression Cages ===\n\n");

    var v8CageBase = getV8CageBase();
    if (v8CageBase) {
        host.diagnostics.debugLog("  V8 Cage Base:     0x" + v8CageBase + "\n");
        host.diagnostics.debugLog("    Formula: Full = CageBase + SignExtend32(Compressed)\n\n");
    } else {
        host.diagnostics.debugLog("  V8 Cage Base:     (not found)\n\n");
    }

    var cppgcCageBase = getCppgcCageBase();
    if (cppgcCageBase) {
        host.diagnostics.debugLog("  Oilpan Cage Base: 0x" + cppgcCageBase + "\n");
        host.diagnostics.debugLog("    Formula: Full = (SignExtend32(Compressed) << 1) & Base\n\n");
    } else {
        host.diagnostics.debugLog("  Oilpan Cage Base: (not found)\n\n");
    }

    host.diagnostics.debugLog("  Commands:\n");
    host.diagnostics.debugLog("    !decompress <ptr>      - V8 decompression\n");
    host.diagnostics.debugLog("    !decompress_gc <ptr>   - Oilpan/cppgc decompression\n\n");

    return "";
}

/// Decompress command - exposed to user
function decompress(ptr) {
    if (!ptr) {
        host.diagnostics.debugLog("\n=== V8 Pointer Decompression ===\n\n");
        host.diagnostics.debugLog("  Usage: !decompress <compressed_ptr>\n");
        host.diagnostics.debugLog("  Example: !decompress 0x12345678\n\n");
        return "";
    }

    var result = decompressV8Ptr(ptr);
    if (result) {
        host.diagnostics.debugLog("\n  Compressed: " + ptr + "\n");
        host.diagnostics.debugLog("  Full ptr:   0x" + result + "\n\n");
    } else {
        host.diagnostics.debugLog("\n  Could not decompress - cage base not found.\n");
        host.diagnostics.debugLog("  Try !v8_cage to see cage info.\n\n");
    }

    return "";
}

/// Decompress Oilpan/cppgc pointer - exposed to user
function decompress_gc(ptr) {
    if (!ptr) {
        host.diagnostics.debugLog("\n=== Oilpan/cppgc Pointer Decompression ===\n\n");
        host.diagnostics.debugLog("  Usage: !decompress_gc <compressed_ptr>\n");
        host.diagnostics.debugLog("  Example: !decompress_gc 0x12345678\n\n");
        host.diagnostics.debugLog("  Used for blink::Member<T>, cppgc::internal::BasicMember<T>\n\n");
        return "";
    }

    // Use the decompression function
    var result = decompressCppgcPtr(ptr);

    if (result === null) {
        host.diagnostics.debugLog("\n  Could not decompress - cage base not found.\n");
        host.diagnostics.debugLog("  Try !decompress_gc <ptr> <context_address> to derive base from an object.\n\n");
    } else {
        host.diagnostics.debugLog("\n  Compressed: " + ptr + "\n");
        host.diagnostics.debugLog("  Full ptr:   0x" + result.toString(16) + "\n\n");
    }

    return "";
}


/// Helper: Set multiple breakpoints with a title and description
function set_breakpoints(title, targets, description) {
    host.diagnostics.debugLog("\n=== " + title + " ===\n\n");
    var ctl = host.namespace.Debugger.Utility.Control;

    for (var i = 0; i < targets.length; i++) {
        host.diagnostics.debugLog("  bp " + targets[i] + "\n");
        try { ctl.ExecuteCommand("bp " + targets[i]); } catch (e) { }
    }

    if (description) {
        host.diagnostics.debugLog("\n  Useful for: " + description + "\n\n");
    }
    return "";
}

/// Helper: Parse WinDbg '|' command to map PIDs to System IDs
function getPidToSysIdMap() {
    var ctl = host.namespace.Debugger.Utility.Control;
    var map = new Map();
    try {
        var lines = ctl.ExecuteCommand("|");
        for (var line of lines) {
            // Match: <sysId> id: <hexPid> (ignore leading . or whitespace)
            // Simply looking for the pattern "digits id: hex" is robust enough
            var match = line.match(/(\d+)\s+id:\s*([0-9a-fA-F]+)/);
            if (match) {
                map.set(parseInt(match[2], 16), parseInt(match[1]));
            }
        }
    } catch (e) {
        host.diagnostics.debugLog("Debug: Failed to parse process map: " + e.message + "\n");
    }
    return map;
}

/// Helper: Safely get process info (type, extra, cmdline) given a process object and system ID.
/// Handles context switching and the "locked process = renderer" heuristic.
function getProcessInfoSafe(proc, sysId) {
    var ctl = host.namespace.Debugger.Utility.Control;
    var cmdLine = "";
    var readSuccess = false;

    // 1. Try to read command line
    try {
        if (sysId !== undefined && sysId !== null && sysId !== "?") {
            try { ctl.ExecuteCommand("|" + sysId + "s"); } catch (e) { }
        }

        var peb = proc.Environment.EnvironmentBlock;
        var cmdLinePtr = peb.ProcessParameters.CommandLine.Buffer;
        cmdLine = host.memory.readWideString(cmdLinePtr);
        readSuccess = true;
    } catch (e) {
        readSuccess = false;
    }

    // 2. Parse or Apply Heuristic
    if (readSuccess) {
        var info = parseProcessInfo(cmdLine);
        return {
            type: info.type,
            extra: info.extra,
            cmdLine: cmdLine,
            locked: false
        };
    } else {
        // Heuristic: If we can't read the command line in a debugged process,
        // it is almost certainly a sandboxed Renderer process.
        return {
            type: "renderer",
            extra: "(sandboxed/locked)",
            cmdLine: "",
            locked: true
        };
    }
}

/// Helper: Find the browser process System ID
function get_browser_sysid() {
    var processes = host.currentSession.Processes;
    var pidToSysId = getPidToSysIdMap();

    for (var proc of processes) {
        var pid = parseInt(proc.Id.toString());
        if (pidToSysId.has(pid)) {
            var sysId = pidToSysId.get(pid);
            var info = getProcessInfoSafe(proc, sysId);
            if (info.type === "browser") {
                return sysId;
            }
        }
    }
    return null;
}

/// Helper: Get map of Renderer Client ID -> Site Lock URL
/// Uses GetProcessLock to query each child ID individually.
/// @param browserSysId - WinDbg system ID for the browser process
/// @param childIds - Array of child IDs to query (from command line parsing)
function get_site_locks(browserSysId, childIds) {
    var locks = new Map();
    var ctl = host.namespace.Debugger.Utility.Control;

    if (browserSysId === null || !childIds || childIds.length === 0) {
        return locks;
    }

    try {
        // Step 1: Get the GetInstance symbol address
        var funcAddr = null;
        try {
            var xOutput = ctl.ExecuteCommand("x chrome!content::ChildProcessSecurityPolicyImpl::GetInstance");
            for (var xLine of xOutput) {
                var lineStr = xLine.toString();
                var match = lineStr.match(/^([0-9a-fA-F`]+)/);
                if (match) {
                    funcAddr = match[1];
                    break;
                }
            }
        } catch (xErr) { return locks; }
        if (!funcAddr) return locks;

        // Step 2: Find a browser with chrome.dll and accessible singleton

        // Get all browser process IDs
        var browserIds = [];
        var processes = host.currentSession.Processes;
        var pidToSysId = getPidToSysIdMap();

        for (var proc of processes) {
            var pid = parseInt(proc.Id.toString());
            if (pidToSysId.has(pid)) {
                var sysId = pidToSysId.get(pid);
                var info = getProcessInfoSafe(proc, sysId);
                if (info.type === "browser") {
                    browserIds.push(sysId);
                }
            }
        }


        var instanceAddr = null;
        var workingBrowserId = null;

        for (var bi = 0; bi < browserIds.length; bi++) {
            var tryBrowserId = browserIds[bi];

            try {
                ctl.ExecuteCommand("|" + tryBrowserId + "s");

                // Check if chrome is loaded in this browser
                var lmOut = ctl.ExecuteCommand("lm m chrome");
                var hasChrome = false;
                for (var lmLine of lmOut) {
                    var lmStr = lmLine.toString();
                    if (lmStr.indexOf("chrome") !== -1 && lmStr.indexOf("start") === -1 && lmStr.indexOf("Browse") === -1) {
                        hasChrome = true;
                        break;
                    }
                }

                if (!hasChrome) continue;

                // Use poi() to read the singleton pointer from the correct process context
                var disasm = ctl.ExecuteCommand("u " + funcAddr + " L15");
                for (var dLine of disasm) {
                    var dLineStr = dLine.toString();
                    var addrMatch = dLineStr.match(/\(([0-9a-fA-F`]+)\)\]/);
                    if (addrMatch) {
                        var addrStr = addrMatch[1].replace(/`/g, "");
                        try {
                            var poiOut = ctl.ExecuteCommand("? poi(0x" + addrStr + ")");
                            for (var poiLine of poiOut) {
                                var poiMatch = poiLine.toString().match(/= ([0-9a-fA-F`]+)/);
                                if (poiMatch) {
                                    var ptrVal = poiMatch[1].replace(/`/g, "");
                                    if (ptrVal !== "0" && ptrVal !== "00000000" && ptrVal.length > 4) {
                                        var candidateAddr = "0x" + ptrVal;

                                        // Verify memory is accessible
                                        var memoryOk = false;
                                        try {
                                            var dqsCheck = ctl.ExecuteCommand("dqs " + candidateAddr + " L1");
                                            for (var dqsLine of dqsCheck) {
                                                var dqsStr = dqsLine.toString();
                                                if (dqsStr.indexOf("????????") === -1 && dqsStr.indexOf(ptrVal.substring(0, 8)) !== -1) {
                                                    memoryOk = true;
                                                }
                                            }
                                        } catch (e) { }

                                        if (memoryOk) {
                                            instanceAddr = candidateAddr;
                                            workingBrowserId = tryBrowserId;
                                            break;
                                        }
                                    }
                                }
                            }
                        } catch (e) { }
                        if (instanceAddr) break;
                    }
                }

                if (instanceAddr) break;

            } catch (e) { }
        }

        if (!instanceAddr) return locks;

        // Step 3: Enumerate all entries in security_state_ map
        try {
            var enumCmd = "dx -r6 ((chrome!content::ChildProcessSecurityPolicyImpl*)" + instanceAddr + ")->security_state_";

            var enumOutput = ctl.ExecuteCommand(enumCmd);
            var currentChildId = null;
            var currentLockUrl = null;
            var lineCount = 0;

            for (var line of enumOutput) {
                var lineStr = line.toString();
                // Look for child ID in "first : N" pattern at appropriate indent level
                // Only match lines that look like top-level security_state_ entries
                if (lineStr.indexOf("first") !== -1 && lineStr.indexOf("[Type:") !== -1) {
                    var firstMatch = lineStr.match(/first\s*:\s*(\d+)/);
                    if (firstMatch) {
                        // Save previous entry if we had a lock URL
                        if (currentChildId !== null && currentLockUrl !== null) {
                            locks.set(currentChildId.toString(), currentLockUrl);
                        }
                        currentChildId = parseInt(firstMatch[1]);
                        currentLockUrl = null;
                    }
                }

                // Look for site_url_ with URL - only capture the first one per child ID
                if ((lineStr.indexOf("site_url_") !== -1 || lineStr.indexOf("lock_url_") !== -1) && currentLockUrl === null) {
                    var urlMatch = lineStr.match(/"(https?:\/\/[^"]+)"/) ||
                        lineStr.match(/"(chrome-extension:\/\/[^"]+)"/) ||
                        lineStr.match(/"(chrome:\/\/[^"]+)"/);
                    if (urlMatch && currentChildId !== null) {
                        currentLockUrl = urlMatch[1];
                    }
                }

            }

            // Save last entry
            if (currentChildId !== null && currentLockUrl !== null) {
                locks.set(currentChildId.toString(), currentLockUrl);
            }
        } catch (e) { }
    } catch (e) { }

    return locks;
}


/// =============================================================================
/// PROCESS IDENTIFICATION
/// =============================================================================

/// Get the command line for the current process
function getCommandLine() {
    try {
        var peb = host.currentProcess.Environment.EnvironmentBlock;
        var cmdLine = peb.ProcessParameters.CommandLine.Buffer;
        return host.memory.readWideString(cmdLine);
    } catch (e) {
        return "";
    }
}

/// Identify the current Chrome process type (and site if renderer)
function chrome_process_type() {
    var cmdLine = getCommandLine();
    var info;

    if (!cmdLine || cmdLine === "") {
        info = { type: "renderer", extra: "(sandboxed/locked)" };
    } else {
        info = parseProcessInfo(cmdLine);
    }

    var pid = host.currentProcess.Id;
    var pidVal = parseInt(pid.toString());

    host.diagnostics.debugLog("\n");
    host.diagnostics.debugLog("  PID:  " + pidVal + "\n");
    host.diagnostics.debugLog("  Type: " + info.type);
    if (info.extra) {
        host.diagnostics.debugLog(" (" + info.extra + ")");
    }
    host.diagnostics.debugLog("\n");

    // If renderer, also show the locked site
    if (info.type === "renderer") {
        try {
            var site = renderer_site();
            // renderer_site already prints output, but let's make it cleaner
        } catch (e) { }
    }

    return info.type;
}

/// Display parsed command line switches
function chrome_cmdline() {
    var cmdLine = getCommandLine();

    if (cmdLine === "") {
        return "Unable to read command line (process may be sandboxed/locked)";
    }

    host.diagnostics.debugLog("\n=== Chrome Command Line ===\n\n");

    // Parse and display switches
    var switches = [];
    var regex = /--([\w-]+)(=("[^"]*"|[^\s]*))?/g;
    var match;

    while ((match = regex.exec(cmdLine)) !== null) {
        var switchName = match[1];
        var switchValue = match[3] || "";
        switches.push({ name: switchName, value: switchValue.replace(/"/g, '') });
    }

    // Categorize and display
    var securitySwitches = ["no-sandbox", "disable-web-security", "disable-site-isolation-trials",
        "site-per-process", "disable-features", "enable-features"];
    var processSwitches = ["type", "renderer-client-id", "utility-sub-type", "field-trial-handle"];

    host.diagnostics.debugLog("  Security-Relevant Switches:\n");
    host.diagnostics.debugLog("  " + "-".repeat(60) + "\n");
    for (var i = 0; i < switches.length; i++) {
        if (securitySwitches.indexOf(switches[i].name) !== -1) {
            host.diagnostics.debugLog("    --" + switches[i].name);
            if (switches[i].value) {
                host.diagnostics.debugLog("=" + switches[i].value);
            }
            host.diagnostics.debugLog("\n");
        }
    }

    host.diagnostics.debugLog("\n  Process Switches:\n");
    host.diagnostics.debugLog("  " + "-".repeat(60) + "\n");
    for (var i = 0; i < switches.length; i++) {
        if (processSwitches.indexOf(switches[i].name) !== -1) {
            host.diagnostics.debugLog("    --" + switches[i].name);
            if (switches[i].value) {
                host.diagnostics.debugLog("=" + switches[i].value);
            }
            host.diagnostics.debugLog("\n");
        }
    }

    host.diagnostics.debugLog("\n  Full command line:\n");
    host.diagnostics.debugLog("  " + cmdLine.substring(0, 200) + "...\n\n");

    return "";
}

/// Helper to parse process info from command line
function parseProcessInfo(cmdLine) {
    if (!cmdLine || cmdLine === "") return { type: "unknown", extra: "" };

    var typeMatch = cmdLine.match(/--type=([^\s"]+)/);
    var extra = "";

    if (typeMatch) {
        var type = typeMatch[1];

        if (type === "renderer") {
            var clientMatch = cmdLine.match(/--renderer-client-id=(\d+)/);
            if (clientMatch) extra = "client=" + clientMatch[1];
        } else if (type === "utility") {
            var utilMatch = cmdLine.match(/--utility-sub-type=([^\s"]+)/);
            if (utilMatch) {
                extra = utilMatch[1].split('.').pop();
            }
        }
        return { type: type, extra: extra };
    }

    // No --type= flag. Check if this looks like the main browser process.
    // Browser process has chrome.exe in path but NO --type, NO --monitor-self flags
    if (cmdLine.toLowerCase().indexOf("chrome.exe") !== -1) {
        // Check for crashpad-handler (monitor-self flag or crash handler path)
        if (cmdLine.indexOf("--monitor-self") !== -1 || cmdLine.indexOf("crashpad") !== -1) {
            return { type: "crashpad-handler", extra: "" };
        }
        // Check for child process indicator flags that main browser wouldn't have
        if (cmdLine.indexOf("--enable-features") !== -1 &&
            cmdLine.indexOf("--field-trial-handle") !== -1) {
            // This is the main browser process 
            return { type: "browser", extra: "" };
        }
        // If it has very minimal command line, it might be browser
        if (cmdLine.length < 500 || cmdLine.indexOf("--user-data-dir") !== -1) {
            return { type: "browser", extra: "" };
        }
    }

    // Default to unknown for unrecognized processes
    return { type: "unknown", extra: "" };
}

/// List all Chrome processes in the debug session with site isolation info
function chrome_processes() {
    host.diagnostics.debugLog("\n=== Chrome Processes in Debug Session ===\n\n");

    var ctl = host.namespace.Debugger.Utility.Control;
    var processes = host.currentSession.Processes;

    // 1. Get Map
    var pidToSysId = getPidToSysIdMap();
    var originalId = 0;

    // Remember which process we're currently in
    try {
        var currentPid = parseInt(host.currentProcess.Id.toString());
        if (pidToSysId.has(currentPid)) {
            originalId = pidToSysId.get(currentPid);
        }
    } catch (e) { }

    // 2. First gather process info and find browser
    var browserSysId = null;
    var browserCmdLine = "";
    var processInfoList = [];

    for (var proc of processes) {
        try {
            var pid = parseInt(proc.Id.toString());
            var sysId = pidToSysId.has(pid) ? pidToSysId.get(pid) : "?";
            var info = getProcessInfoSafe(proc, sysId);

            processInfoList.push({
                pid: pid,
                sysId: sysId,
                type: info.type,
                extra: info.extra,
                clientId: null
            });

            // Extract renderer client ID for later matching
            if (info.type === "renderer" && info.extra) {
                var clientMatch = info.extra.match(/client=(\d+)/);
                if (clientMatch) {
                    processInfoList[processInfoList.length - 1].clientId = clientMatch[1];
                }
            }

            if (info.type === "browser") {
                browserSysId = sysId;
                browserCmdLine = info.cmdLine;
            }
        } catch (e) { }
    }

    // 3. Collect all child IDs for site lock lookup
    var childIds = [];
    for (var pInfo of processInfoList) {
        if (pInfo.clientId) {
            childIds.push(parseInt(pInfo.clientId));
        }
    }

    // 4. Get Site Isolation Runtime State (from browser process)
    var childIdToSite = get_site_locks(browserSysId, childIds);

    // 5. Display site isolation configuration
    var sitePerProcess = browserCmdLine.indexOf("--site-per-process") !== -1;
    var disableSI = browserCmdLine.indexOf("--disable-site-isolation") !== -1;
    var isolateOrigins = browserCmdLine.indexOf("--isolate-origins") !== -1;

    host.diagnostics.debugLog("  [Site Isolation] ");
    if (disableSI) {
        host.diagnostics.debugLog("DISABLED (--disable-site-isolation)\n");
    } else if (sitePerProcess) {
        host.diagnostics.debugLog("ENABLED (--site-per-process)\n");
    } else if (isolateOrigins) {
        host.diagnostics.debugLog("PARTIAL (--isolate-origins)\n");
    } else {
        host.diagnostics.debugLog("Default\n");
    }
    host.diagnostics.debugLog("\n");

    // 6. Display process list with site info inline
    host.diagnostics.debugLog("  ID    PID       Type            Site / Extra Info\n");
    host.diagnostics.debugLog("  " + "-".repeat(70) + "\n");

    for (var pInfo of processInfoList) {
        var displayExtra = pInfo.extra;

        // For renderers, show site URL if available
        if (pInfo.type === "renderer" && pInfo.clientId) {
            var site = childIdToSite.get(pInfo.clientId);
            if (site && site !== "(no lock)") {
                displayExtra = site;
            } else if (pInfo.extra) {
                displayExtra = pInfo.extra;
            }
        }

        host.diagnostics.debugLog("  " + pInfo.sysId.toString().padEnd(6) +
            pInfo.pid.toString().padEnd(10) +
            pInfo.type.padEnd(16) +
            displayExtra + "\n");
    }

    // Switch back to original process
    try {
        ctl.ExecuteCommand("|" + originalId + "s");
    } catch (e) { }

    host.diagnostics.debugLog("\n  Use |<ID>s to switch to a process (e.g., |1s)\n\n");
    return "";
}

/// Show the locked site for the current renderer process
function renderer_site() {
    var ctl = host.namespace.Debugger.Utility.Control;

    // Get current process info
    var cmdLine = getCommandLine();
    var info = cmdLine ? parseProcessInfo(cmdLine) : { type: "renderer", extra: "(sandboxed/locked)" };

    if (info.type !== "renderer") {
        host.diagnostics.debugLog("\n  Not a renderer process (current: " + info.type + ")\n\n");
        return "";
    }

    // Get client ID from command line or extra info
    var clientId = null;
    if (cmdLine) {
        var clientMatch = cmdLine.match(/--renderer-client-id=(\d+)/);
        if (clientMatch) clientId = clientMatch[1];
    }

    if (!clientId && info.extra) {
        var extraMatch = info.extra.match(/client=(\d+)/);
        if (extraMatch) clientId = extraMatch[1];
    }

    if (!clientId) {
        host.diagnostics.debugLog("\n  Unable to determine renderer client ID\n\n");
        return "";
    }

    // Remember current process
    var pidToSysId = getPidToSysIdMap();
    var currentPid = parseInt(host.currentProcess.Id.toString());
    var originalId = pidToSysId.has(currentPid) ? pidToSysId.get(currentPid) : 0;

    // Find browser process
    var browserSysId = get_browser_sysid();

    if (browserSysId === null) {
        host.diagnostics.debugLog("\n  Unable to find browser process\n\n");
        return "";
    }

    // Query security state via helper
    var site = "(unknown)";
    try {
        var locks = get_site_locks(browserSysId, [parseInt(clientId)]);
        if (locks.has(clientId)) {
            site = locks.get(clientId);
        }
    } catch (e) {
        site = "(error: " + e.message + ")";
    }

    // Switch back
    try {
        ctl.ExecuteCommand("|" + originalId + "s");
    } catch (e) { }

    host.diagnostics.debugLog("\n");
    host.diagnostics.debugLog("  Renderer Client ID: " + clientId + "\n");
    host.diagnostics.debugLog("  Locked Site:        " + site + "\n");
    host.diagnostics.debugLog("\n");

    return site;
}

/// =============================================================================
/// FUNCTION PATCHING & ORIGIN SPOOFING
/// =============================================================================

/// Patch a function to return a specific value
/// Usage: !patch_function "FunctionName" "return_value"
function patch_function(funcName, returnValue) {
    host.diagnostics.debugLog("\n=== Patch Function ===\n\n");

    if (!funcName || funcName === "") {
        host.diagnostics.debugLog("  Usage: !patch(\"ClassName::FunctionName\",\"value\")\n\n");
        host.diagnostics.debugLog("  Values: true, false, 0, 1, 0x1234, or any number\n\n");
        host.diagnostics.debugLog("  Examples:\n");
        host.diagnostics.debugLog("    !patch(\"FullscreenIsSupported\",\"false\")\n");
        host.diagnostics.debugLog("    !patch(\"IsFeatureEnabled\",\"0\")\n");
        host.diagnostics.debugLog("    !patch(\"*CanAccess*\",\"true\")\n\n");
        host.diagnostics.debugLog("  Auto-detects inlining and patches callers if needed.\n\n");
        return "";
    }

    var ctl = host.namespace.Debugger.Utility.Control;

    // Parse return value - support true/false/hex/decimal
    var retVal = 0;
    if (returnValue === undefined || returnValue === null || returnValue === "") {
        retVal = 0;
    } else if (returnValue === "true" || returnValue === "TRUE" || returnValue === "True") {
        retVal = 1;
    } else if (returnValue === "false" || returnValue === "FALSE" || returnValue === "False") {
        retVal = 0;
    } else if (returnValue.toString().startsWith("0x") || returnValue.toString().startsWith("0X")) {
        retVal = parseInt(returnValue, 16);
    } else {
        retVal = parseInt(returnValue) || 0;
    }

    host.diagnostics.debugLog("  Return value: " + retVal + (retVal === 0 ? " (false)" : retVal === 1 ? " (true)" : "") + "\\n\\n");

    try {
        var symbols = [];

        // If it contains '!' it's already a full symbol - resolve its address
        if (funcName.indexOf("!") !== -1) {
            try {
                var xOut = ctl.ExecuteCommand("x " + funcName);
                for (var xLine of xOut) {
                    var match = xLine.toString().match(/^([0-9a-fA-F`]+)\s+(.+)/);
                    if (match) {
                        symbols.push({ addr: match[1].replace(/`/g, ""), name: match[2].trim() });
                    }
                }
            } catch (e) { }
        } else {
            // Search for matching symbols
            host.diagnostics.debugLog("  Searching for: *" + funcName + "*\n\n");

            var patterns = [
                "chrome!*" + funcName + "*",
                "blink_core!*" + funcName + "*",
                "blink_modules!*" + funcName + "*"
            ];

            for (var pattern of patterns) {
                try {
                    var output = ctl.ExecuteCommand("x " + pattern);
                    for (var line of output) {
                        var lineStr = line.toString();
                        // Extract BOTH the address and symbol name
                        var match = lineStr.match(/^([0-9a-fA-F`]+)\s+(.+)/);
                        if (match) {
                            var addr = match[1].replace(/`/g, "");
                            var symName = match[2].trim();
                            // Store as object with address and name
                            var exists = false;
                            for (var s of symbols) {
                                if (s.addr === addr) { exists = true; break; }
                            }
                            if (!exists) {
                                symbols.push({ addr: addr, name: symName });
                            }
                        }
                    }
                } catch (e) { }
            }
        }

        if (symbols.length === 0) {
            host.diagnostics.debugLog("  No matching symbols found.\n\n");
            return "";
        }

        host.diagnostics.debugLog("  Found " + symbols.length + " symbol(s):\n\n");

        // Direct code patching: write "mov eax, VALUE; ret" at function start
        // This is more reliable than breakpoints for getters/inlined code
        // x64: mov eax, imm32 = B8 xx xx xx xx; ret = C3 (6 bytes total)
        // For 0: xor eax,eax = 31 C0; ret = C3 (3 bytes)

        var count = 0;
        for (var sym of symbols) {
            if (count >= 10) {
                host.diagnostics.debugLog("  ... (limited to 10)\n");
                break;
            }
            try {
                var funcAddr = sym.addr;

                // Write patch bytes directly to function
                // mov eax, VALUE (B8 + 4 bytes little-endian) then ret (C3)
                if (retVal === 0) {
                    // xor eax, eax; ret = 31 C0 C3
                    ctl.ExecuteCommand("eb 0x" + funcAddr + " 31 C0 C3");
                } else if (retVal === 1) {
                    // mov eax, 1; ret = B8 01 00 00 00 C3
                    ctl.ExecuteCommand("eb 0x" + funcAddr + " B8 01 00 00 00 C3");
                } else {
                    // mov eax, VALUE; ret
                    var b0 = retVal & 0xFF;
                    var b1 = (retVal >> 8) & 0xFF;
                    var b2 = (retVal >> 16) & 0xFF;
                    var b3 = (retVal >> 24) & 0xFF;
                    ctl.ExecuteCommand("eb 0x" + funcAddr + " B8 " +
                        b0.toString(16).padStart(2, '0') + " " +
                        b1.toString(16).padStart(2, '0') + " " +
                        b2.toString(16).padStart(2, '0') + " " +
                        b3.toString(16).padStart(2, '0') + " C3");
                }

                host.diagnostics.debugLog("  [PATCHED] " + sym.name + " @ 0x" + funcAddr + "\n");
                count++;
            } catch (e) {
                host.diagnostics.debugLog("  [FAILED] " + sym.name + " @ 0x" + sym.addr + ": " + e.message + "\n");
            }
        }

        host.diagnostics.debugLog("\n  " + count + " function(s) patched -> return " + retVal + "\n");
        host.diagnostics.debugLog("  NOTE: Patches are direct code modifications (not breakpoints)\n");
        host.diagnostics.debugLog("  TIP: V8 caches results - navigate to a new page to see effect in JS\n\n");

        // Auto inlining detection: analyze if function might be inlined
        // by looking for callers that contain calls to related functions
        if (count > 0 && funcName.indexOf("!") === -1) {
            // Extract short name for caller search
            var shortName = funcName;
            if (shortName.indexOf("::") !== -1) {
                var parts = shortName.split("::");
                shortName = parts[parts.length - 1];
            }

            // Look for V8 accessor callbacks that might inline this function
            var callerPatterns = [
                "chrome!*" + shortName + "*AttributeGetCallback*",
                "chrome!*" + shortName + "*Callback*"
            ];

            var callers = [];
            for (var callerPattern of callerPatterns) {
                try {
                    var callerOutput = ctl.ExecuteCommand("x " + callerPattern);
                    for (var callerLine of callerOutput) {
                        var callerMatch = callerLine.toString().match(/^([0-9a-fA-F`]+)\\s+(.+)/);
                        if (callerMatch) {
                            var callerAddr = callerMatch[1].replace(/`/g, "");
                            var callerName = callerMatch[2].trim();
                            // Check if this caller is different from what we patched
                            var isDifferent = true;
                            for (var patched of symbols) {
                                if (patched.addr === callerAddr) { isDifferent = false; break; }
                            }
                            if (isDifferent) {
                                callers.push({ addr: callerAddr, name: callerName });
                            }
                        }
                    }
                } catch (e) { }
            }

            if (callers.length > 0) {
                host.diagnostics.debugLog("\\n  Found " + callers.length + " potential caller(s) that may inline this function.\\n");
                host.diagnostics.debugLog("  If patch doesn't work, try: !patch(\"<caller_name>\",\"" + retVal + "\")\\n");
                for (var c = 0; c < Math.min(callers.length, 3); c++) {
                    host.diagnostics.debugLog("    - " + callers[c].name + "\\n");
                }
                host.diagnostics.debugLog("\\n");
            }
        }

    } catch (e) {
        host.diagnostics.debugLog("  Error: " + e.message + "\n\n");
    }

    return "";
}

/// Spoof renderer origin by patching the host string in memory
/// Extract host from a URL or return the string if it looks like a host
function getHostFromUrl(url) {
    if (!url) return "";
    var match = url.match(/^https?:\/\/([^\/]+)/);
    if (match) {
        return match[1];
    }
    return url;
}

/// Usage: !spoof_origin "https://target.com"
function spoof_origin(targetUrl) {
    host.diagnostics.debugLog("\n=== Spoof Origin ===\n\n");

    var ctl = host.namespace.Debugger.Utility.Control;

    if (!targetUrl || targetUrl === "") {
        host.diagnostics.debugLog("  Usage: !spoof(\"https://target.com\")\n\n");
        host.diagnostics.debugLog("  Example: !spoof(\"https://google.com\")\n\n");
        host.diagnostics.debugLog("  Auto-detects current origin and patches all occurrences.\n\n");
        return "";
    }

    // Parse target URL to get host
    var targetHost = getHostFromUrl(targetUrl);

    // Get current origin from !site
    host.diagnostics.debugLog("  Target: " + targetHost + "\n");
    host.diagnostics.debugLog("  Detecting current origin...\n");

    var currentHost = "";
    try {
        var site = renderer_site();
        if (site && site !== "" && site !== "(unknown)") {
            var extracted = getHostFromUrl(site);
            // Verify it looks like a domain if it didn't come from a URL match
            // (getHostFromUrl returns raw input fallback, so we check for dot or if it changed)
            if (extracted !== site || site.indexOf(".") !== -1) {
                currentHost = extracted;
            }
        }
    } catch (e) { }

    if (!currentHost) {
        host.diagnostics.debugLog("\n  Could not detect current origin.\n");
        host.diagnostics.debugLog("  Make sure you're in a renderer with a loaded page.\n\n");
        return "";
    }

    host.diagnostics.debugLog("  Current: " + currentHost + "\n\n");

    if (targetHost.length > currentHost.length) {
        host.diagnostics.debugLog("  WARNING: Target longer than current, may corrupt memory.\n\n");
    }

    try {
        host.diagnostics.debugLog("  Searching for \"" + currentHost + "\"...\n");

        // Search entire user-mode address space
        var searchCmd = 's -a 0 L?0x7fffffffffff "' + currentHost + '"';
        var output = ctl.ExecuteCommand(searchCmd);

        var addresses = [];
        for (var line of output) {
            var lineStr = line.toString();
            var match = lineStr.match(/^([0-9a-fA-F`]+)/);
            if (match) {
                addresses.push(match[1].replace(/`/g, ""));
            }
        }

        if (addresses.length === 0) {
            host.diagnostics.debugLog("  No matches found.\n\n");
            return "";
        }

        host.diagnostics.debugLog("  Found " + addresses.length + " occurrence(s), patching...\n\n");

        var patched = 0;
        for (var addr of addresses) {
            try {
                ctl.ExecuteCommand('ea ' + addr + ' "' + targetHost + '"');
                patched++;
            } catch (e) { }
        }

        host.diagnostics.debugLog("  Patched " + patched + " location(s)\n\n");

    } catch (e) {
        host.diagnostics.debugLog("  Error: " + e.message + "\n\n");
    }

    return "";
}



/// =============================================================================
/// SANDBOX INSPECTION
/// =============================================================================

/// Check sandbox state
function sandbox_state() {
    host.diagnostics.debugLog("\n=== Sandbox State ===\n\n");

    var processType = chrome_process_type();

    if (processType === "browser") {
        host.diagnostics.debugLog("  Browser process - not sandboxed\n\n");
        return "browser (not sandboxed)";
    }

    // Try to find sandbox state symbols
    host.diagnostics.debugLog("  Checking sandbox state...\n\n");

    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        // Try to examine process token
        host.diagnostics.debugLog("  Token Information:\n");
        host.diagnostics.debugLog("  " + "-".repeat(40) + "\n");

        // Get token integrity level using !token
        var tokenOutput = ctl.ExecuteCommand("!token -n");
        for (var line of tokenOutput) {
            if (line.indexOf("Impersonation") !== -1 ||
                line.indexOf("Integrity") !== -1 ||
                line.indexOf("Restricted") !== -1) {
                host.diagnostics.debugLog("    " + line + "\n");
            }
        }
    } catch (e) {
        host.diagnostics.debugLog("  Unable to query token (symbols may be needed)\n");
    }

    host.diagnostics.debugLog("\n");

    // Check for sandbox::TargetServicesBase if symbols are available
    host.diagnostics.debugLog("  Sandbox Breakpoints (for detailed analysis):\n");
    host.diagnostics.debugLog("  " + "-".repeat(40) + "\n");
    host.diagnostics.debugLog("    bp sandbox!TargetServicesBase::Init\n");
    host.diagnostics.debugLog("    bp sandbox!TargetServicesBase::LowerToken\n");
    host.diagnostics.debugLog("\n");

    return "";
}

/// Analyze process token
function sandbox_token() {
    host.diagnostics.debugLog("\n=== Process Token Analysis ===\n\n");

    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        // Get detailed token info
        host.diagnostics.debugLog("  Running !token...\n\n");
        var tokenOutput = ctl.ExecuteCommand("!token");
        for (var line of tokenOutput) {
            host.diagnostics.debugLog("  " + line + "\n");
        }
    } catch (e) {
        host.diagnostics.debugLog("  Error: " + e.message + "\n");
        host.diagnostics.debugLog("  Try: .reload /f ntdll.dll\n");
    }

    host.diagnostics.debugLog("\n");
    return "";
}

/// =============================================================================
/// SECURITY BREAKPOINTS
/// =============================================================================

/// Set breakpoint on renderer process launch
function bp_renderer_launch() {
    return set_breakpoints(
        "Renderer Launch Breakpoints",
        [
            "content!RenderProcessHostImpl::Init",
            "content!RenderProcessHostImpl::OnProcessLaunched",
            "content!ChildProcessLauncher::Launch"
        ],
        "Breaking when renderer processes start"
    );
}

/// Set breakpoint on sandbox token lowering
function bp_sandbox_lower() {
    return set_breakpoints(
        "Sandbox Token Breakpoints",
        [
            "sandbox!TargetServicesBase::LowerToken",
            "sandbox!ProcessState::SetRevertedToSelf"
        ],
        "Breaking when sandbox restricts token"
    );
}

/// Set breakpoint on Mojo interface binding
function bp_mojo_interface() {
    return set_breakpoints(
        "Mojo Interface Breakpoints",
        [
            "content!BrowserInterfaceBrokerImpl::GetInterface",
            "content!RenderProcessHostImpl::BindReceiver",
            "mojo!MessagePipeDispatcher::WriteMessage"
        ],
        "Tracking Mojo IPC"
    );
}

/// Set breakpoint on IPC message dispatch
function bp_ipc_message() {
    return set_breakpoints(
        "IPC Message Breakpoints",
        [
            "content!ChildProcessHost::OnMessageReceived",
            "ipc!ChannelMojo::OnMessageReceived"
        ],
        "IPC message logging"
    );
}



/// =============================================================================
/// PROCESS-SPECIFIC EXECUTION
/// =============================================================================

/// Global storage for attach commands
var g_attachCommands = [];

/// Get the process type of the current process
function getProcessType() {
    // Reuse safe helper logic without context switch (we are in current context)
    try {
        // Reuse logic of chrome_process_type
        var cmdLine = getCommandLine();
        if (!cmdLine || cmdLine === "") {
            return "renderer"; // Heuristic
        }
        var info = parseProcessInfo(cmdLine);
        return info.type;
    } catch (e) {
        return "renderer";
    }
}

/// Check if current process matches a type
function isProcessType(targetType) {
    return getProcessType() === targetType;
}

/// Check if current process is a renderer
function is_renderer() {
    var result = isProcessType("renderer");
    host.diagnostics.debugLog("\n  Current process is " + (result ? "a RENDERER" : "NOT a renderer") + "\n\n");
    return result;
}

/// Generic: Execute command in all processes of a specific type
function runInProcessType(targetType, command) {
    var ctl = host.namespace.Debugger.Utility.Control;

    // If already in the target process type, run directly
    if (isProcessType(targetType)) {
        host.diagnostics.debugLog("  [" + targetType.toUpperCase() + " PID:" + host.currentProcess.Id + "] Executing: " + command + "\n");
        try {
            var output = ctl.ExecuteCommand(command);
            for (var line of output) {
                host.diagnostics.debugLog("  " + line + "\n");
            }
        } catch (e) {
            host.diagnostics.debugLog("  Error: " + e.message + "\n");
        }
        return "executed";
    }

    host.diagnostics.debugLog("\n=== Running in All " + targetType.toUpperCase() + " Processes ===\n\n");

    try {
        // 1. Get Map
        var pidToSysId = getPidToSysIdMap();
        var processes = host.currentSession.Processes;

        var matchCount = 0;
        var matchingSystemIds = [];

        // Find matching processes
        for (var proc of processes) {
            try {
                var pid = parseInt(proc.Id.toString());
                var sysId = pidToSysId.has(pid) ? pidToSysId.get(pid) : null;

                if (sysId === null) continue;

                // 2. Get Safe Info
                var info = getProcessInfoSafe(proc, sysId);

                if (info.type === targetType) {
                    matchingSystemIds.push({ sysId: sysId, pid: pid });
                }
            } catch (e) { }
        }

        if (matchingSystemIds.length === 0) {
            host.diagnostics.debugLog("  No " + targetType + " processes found.\n\n");
            return "no_match";
        }

        host.diagnostics.debugLog("  Found " + matchingSystemIds.length + " " + targetType + " process(es)\n\n");

        // Execute in each matching process
        for (var i = 0; i < matchingSystemIds.length; i++) {
            var info = matchingSystemIds[i];
            host.diagnostics.debugLog("  [" + targetType.toUpperCase() + " PID:" + info.pid + "] Executing: " + command + "\n");

            try {
                ctl.ExecuteCommand("|" + info.sysId + "s");
                var output = ctl.ExecuteCommand(command);
                for (var line of output) {
                    host.diagnostics.debugLog("    " + line + "\n");
                }
                matchCount++;
            } catch (e) {
                host.diagnostics.debugLog("    Error: " + e.message + "\n");
            }
        }

        // Restore original context if possible (approximate)
        try { ctl.ExecuteCommand("|0s"); } catch (e) { }

        host.diagnostics.debugLog("\n  Executed in " + matchCount + " " + targetType + " process(es)\n\n");
        return "executed_in_" + matchCount;

    } catch (e) {
        host.diagnostics.debugLog("Error in runInProcessType: " + e.message + "\n");
        return "error";
    }
}

/// =============================================================================
/// SANDBOX INSPECTION
/// =============================================================================

/// Check sandbox state
function sandbox_state() {
    host.diagnostics.debugLog("\n=== Sandbox State ===\n\n");

    var processType = chrome_process_type();

    if (processType === "browser") {
        host.diagnostics.debugLog("  Browser process - not sandboxed\n\n");
        return "browser (not sandboxed)";
    }

    // Try to find sandbox state symbols
    host.diagnostics.debugLog("  Checking sandbox state...\n\n");

    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        // Try to examine process token
        host.diagnostics.debugLog("  Token Information:\n");
        host.diagnostics.debugLog("  " + "-".repeat(40) + "\n");

        // Get token integrity level using !token
        var tokenOutput = ctl.ExecuteCommand("!token -n");
        for (var line of tokenOutput) {
            if (line.indexOf("Impersonation") !== -1 ||
                line.indexOf("Integrity") !== -1 ||
                line.indexOf("Restricted") !== -1) {
                host.diagnostics.debugLog("    " + line + "\n");
            }
        }
    } catch (e) {
        host.diagnostics.debugLog("  Unable to query token (symbols may be needed)\n");
    }

    host.diagnostics.debugLog("\n");

    // Check for sandbox::TargetServicesBase if symbols are available
    host.diagnostics.debugLog("  Sandbox Breakpoints (for detailed analysis):\n");
    host.diagnostics.debugLog("  " + "-".repeat(40) + "\n");
    host.diagnostics.debugLog("    bp sandbox!TargetServicesBase::Init\n");
    host.diagnostics.debugLog("    bp sandbox!TargetServicesBase::LowerToken\n");
    host.diagnostics.debugLog("\n");

    return "";
}

/// Check sandbox status for ALL processes
function sandbox_status_all() {
    host.diagnostics.debugLog("\n=== Sandbox Status Dashboard ===\n\n");
    host.diagnostics.debugLog("  ID    PID       Type              Integrity Level           Status\n");
    host.diagnostics.debugLog("  " + "-".repeat(90) + "\n");

    var ctl = host.namespace.Debugger.Utility.Control;

    // Use our trusted helpers
    var pidToSysId = getPidToSysIdMap();
    var processes = host.currentSession.Processes;

    // Remember original context
    var originalId = 0;
    try {
        var curPid = parseInt(host.currentProcess.Id.toString());
        if (pidToSysId.has(curPid)) originalId = pidToSysId.get(curPid);
    } catch (e) { }

    for (var proc of processes) {
        try {
            var pid = parseInt(proc.Id.toString());
            var sysId = pidToSysId.has(pid) ? pidToSysId.get(pid) : null;
            if (sysId === null) continue;

            var info = getProcessInfoSafe(proc, sysId);
            var type = info.type;

            // Switch and query token
            ctl.ExecuteCommand("|" + sysId + "s");

            var integrity = "Unknown";
            var status = "Unknown";

            // Run !token to get integrity
            // Output format varies: "Integrity Level: Low" or "IntegrityLevel: Low" or raw SID
            try {
                var output = ctl.ExecuteCommand("!token");
                for (var line of output) {
                    // Match "Integrity Level" or "IntegrityLevel" followed by colon
                    if (/Integrity.*Level.*:/i.test(line)) {
                        var parts = line.split(":");
                        if (parts.length > 1) integrity = parts[1].trim();
                        break;
                    }
                }
            } catch (e) { integrity = "Error reading token"; }

            // Map SIDs to Names if regex didn't catch text
            if (integrity.indexOf("S-1-16-0") !== -1) integrity = "Untrusted (S-1-16-0)";
            else if (integrity.indexOf("S-1-16-4096") !== -1) integrity = "Low (S-1-16-4096)";
            else if (integrity.indexOf("S-1-16-8192") !== -1) integrity = "Medium (S-1-16-8192)";
            else if (integrity.indexOf("S-1-16-12288") !== -1) integrity = "High (S-1-16-12288)";
            else if (integrity.indexOf("S-1-16-16384") !== -1) integrity = "System (S-1-16-16384)";
            else if (integrity.indexOf("S-1-15-2") !== -1) integrity = "AppContainer";

            // Determine status based on type and integrity
            if (type === "browser") {
                // Browser should be Medium or High
                status = (integrity.indexOf("Medium") !== -1 || integrity.indexOf("High") !== -1) ? "OK" : "WARN";
            } else if (type === "renderer") {
                // Renderer MUST be Low, Untrusted, or AppContainer
                if (integrity.indexOf("Untrusted") !== -1 ||
                    integrity.indexOf("Low") !== -1 ||
                    integrity.indexOf("AppContainer") !== -1 ||
                    integrity.indexOf("Restricted") !== -1) {
                    status = "OK (Sandboxed)";
                } else {
                    status = "DANGER (Weak Sandbox)";
                }
            } else if (type === "gpu-process") {
                // GPU varies but usually Low or AppContainer
                status = (integrity.indexOf("Medium") === -1) ? "OK" : "WARN (Medium)";
            } else if (type === "utility") {
                // Utilities should generally be low/untrusted too, but some network/storage run higher
                status = (integrity.indexOf("Medium") === -1) ? "OK" : "Info (Medium)";
            } else {
                status = "-";
            }

            // Shorten integrity string for display
            if (integrity.length > 25) integrity = integrity.substring(0, 22) + "...";

            host.diagnostics.debugLog(
                "  " + sysId.toString().padEnd(6) +
                pid.toString().padEnd(10) +
                type.padEnd(18) +
                integrity.padEnd(26) +
                status + "\n"
            );

        } catch (e) {
            host.diagnostics.debugLog("  Error processing PID " + pid + "\n");
        }
    }

    // Restore context
    try { ctl.ExecuteCommand("|" + originalId + "s"); } catch (e) { }

    host.diagnostics.debugLog("\n");
    return "";
}

/// Analyze process token
function sandbox_token() {
    host.diagnostics.debugLog("\n=== Process Token Analysis ===\n\n");

    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        // Get detailed token info
        host.diagnostics.debugLog("  Running !token...\n\n");
        var tokenOutput = ctl.ExecuteCommand("!token");
        for (var line of tokenOutput) {
            host.diagnostics.debugLog("  " + line + "\n");
        }
    } catch (e) {
        host.diagnostics.debugLog("  Error: " + e.message + "\n");
        host.diagnostics.debugLog("  Try: .reload /f ntdll.dll\n");
    }

    host.diagnostics.debugLog("\n");
    return "";
}

/// =============================================================================
/// SECURITY BREAKPOINTS
/// =============================================================================

/// Set breakpoint on renderer process launch
function bp_renderer_launch() {
    host.diagnostics.debugLog("\n=== Setting Renderer Launch Breakpoints ===\n\n");

    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        // Breakpoint patterns for renderer launch
        var bpTargets = [
            "content!RenderProcessHostImpl::Init",
            "content!RenderProcessHostImpl::OnProcessLaunched",
            "content!ChildProcessLauncher::Launch"
        ];

        for (var i = 0; i < bpTargets.length; i++) {
            host.diagnostics.debugLog("  Setting: bp " + bpTargets[i] + "\n");
            try {
                ctl.ExecuteCommand("bp " + bpTargets[i]);
            } catch (e) {
                host.diagnostics.debugLog("    (symbol not found - may need symbols)\n");
            }
        }

        host.diagnostics.debugLog("\n  Breakpoints set. Use 'bl' to list.\n\n");
    } catch (e) {
        host.diagnostics.debugLog("  Error: " + e.message + "\n");
    }

    return "";
}

/// Set breakpoint on sandbox token lowering
function bp_sandbox_lower() {
    host.diagnostics.debugLog("\n=== Setting Sandbox Token Breakpoints ===\n\n");

    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        var bpTargets = [
            "sandbox!TargetServicesBase::LowerToken",
            "sandbox!ProcessState::SetRevertedToSelf"
        ];

        for (var i = 0; i < bpTargets.length; i++) {
            host.diagnostics.debugLog("  Setting: bp " + bpTargets[i] + "\n");
            try {
                ctl.ExecuteCommand("bp " + bpTargets[i]);
            } catch (e) {
                host.diagnostics.debugLog("    (symbol not found)\n");
            }
        }

        host.diagnostics.debugLog("\n  These breakpoints will hit when sandbox restricts token.\n\n");
    } catch (e) {
        host.diagnostics.debugLog("  Error: " + e.message + "\n");
    }

    return "";
}

/// Set breakpoint on Mojo interface binding
function bp_mojo_interface() {
    host.diagnostics.debugLog("\n=== Setting Mojo Interface Breakpoints ===\n\n");

    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        var bpTargets = [
            "content!BrowserInterfaceBrokerImpl::GetInterface",
            "content!RenderProcessHostImpl::BindReceiver",
            "mojo!MessagePipeDispatcher::WriteMessage"
        ];

        for (var i = 0; i < bpTargets.length; i++) {
            host.diagnostics.debugLog("  Setting: bp " + bpTargets[i] + "\n");
            try {
                ctl.ExecuteCommand("bp " + bpTargets[i]);
            } catch (e) {
                host.diagnostics.debugLog("    (symbol not found)\n");
            }
        }

        host.diagnostics.debugLog("\n  These breakpoints track Mojo IPC.\n\n");
    } catch (e) {
        host.diagnostics.debugLog("  Error: " + e.message + "\n");
    }

    return "";
}

/// Set breakpoint on IPC message dispatch
function bp_ipc_message() {
    host.diagnostics.debugLog("\n=== Setting IPC Message Breakpoints ===\n\n");

    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        var bpTargets = [
            "content!ChildProcessHost::OnMessageReceived",
            "ipc!ChannelMojo::OnMessageReceived"
        ];

        for (var i = 0; i < bpTargets.length; i++) {
            host.diagnostics.debugLog("  Setting: bp " + bpTargets[i] + "\n");
            try {
                ctl.ExecuteCommand("bp " + bpTargets[i]);
            } catch (e) {
                host.diagnostics.debugLog("    (symbol not found)\n");
            }
        }

        host.diagnostics.debugLog("\n");
    } catch (e) {
        host.diagnostics.debugLog("  Error: " + e.message + "\n");
    }

    return "";
}

/// =============================================================================
/// SITE ISOLATION
/// =============================================================================

/// Check Site Isolation status
function site_isolation_status() {
    host.diagnostics.debugLog("\n=== Site Isolation Status ===\n\n");

    var cmdLine = getCommandLine();

    // Check command line flags
    var flags = {
        "site-per-process": cmdLine.indexOf("--site-per-process") !== -1,
        "disable-site-isolation": cmdLine.indexOf("--disable-site-isolation") !== -1,
        "isolate-origins": cmdLine.indexOf("--isolate-origins") !== -1
    };

    host.diagnostics.debugLog("  Command Line Flags:\n");
    host.diagnostics.debugLog("  " + "-".repeat(40) + "\n");
    host.diagnostics.debugLog("    --site-per-process:          " + (flags["site-per-process"] ? "ENABLED" : "not set") + "\n");
    host.diagnostics.debugLog("    --disable-site-isolation:    " + (flags["disable-site-isolation"] ? "WARNING: DISABLED" : "not set") + "\n");
    host.diagnostics.debugLog("    --isolate-origins:           " + (flags["isolate-origins"] ? "ENABLED" : "not set") + "\n");

    // Extract isolated origins if present
    if (flags["isolate-origins"]) {
        var match = cmdLine.match(/--isolate-origins=([^\s"]+)/);
        if (match) {
            host.diagnostics.debugLog("\n  Isolated Origins: " + match[1] + "\n");
        }
    }

    host.diagnostics.debugLog("\n  Runtime Check Breakpoints:\n");
    host.diagnostics.debugLog("  " + "-".repeat(40) + "\n");
    host.diagnostics.debugLog("    bp content!SiteIsolationPolicy::UseDedicatedProcessesForAllSites\n");
    host.diagnostics.debugLog("    bp content!SiteInstanceImpl::GetSiteForURL\n");
    host.diagnostics.debugLog("\n");

    return "";
}

/// List all frames in the current renderer process
function renderer_frames() {
    host.diagnostics.debugLog("\n=== Renderer Frames ===\n\n");

    var ctl;
    try {
        ctl = host.namespace.Debugger.Utility.Control;
    } catch (e) {
        host.diagnostics.debugLog("  Error: Cannot get debugger control interface.\n\n");
        return "";
    }

    // Try to verify we're in a renderer, but don't fail if we can't check
    try {
        var cmdLine = getCommandLine();
        if (cmdLine) {
            var info = parseProcessInfo(cmdLine);
            if (info && info.type !== "renderer") {
                host.diagnostics.debugLog("  Warning: May not be a renderer (detected: " + info.type + ")\n");
                host.diagnostics.debugLog("  Continuing anyway...\n\n");
            }
        }
    } catch (e) {
        host.diagnostics.debugLog("  Could not verify process type (continuing anyway)\n\n");
    }

    try {
        // Find g_frame_map symbol address
        // g_frame_map is a base::LazyInstance<FrameMap>::DestructorAtExit
        // where FrameMap = absl::flat_hash_map<blink::WebFrame*, RenderFrameImpl*>
        host.diagnostics.debugLog("  Step 1: Looking for g_frame_map symbol...\n");

        // First check if chrome module is loaded
        var hasModule = false;
        try {
            var modules = host.currentProcess.Modules;
            for (var mod of modules) {
                var modName = mod.Name.toLowerCase();
                // Look for chrome.dll specifically (not chrome_elf.dll etc.)
                if (modName === "chrome.dll" || modName.endsWith("\\chrome.dll")) {
                    hasModule = true;
                    host.diagnostics.debugLog("    Found module: " + mod.Name + "\n");
                    break;
                }
            }
        } catch (modErr) {
            host.diagnostics.debugLog("    Warning: Could not enumerate modules\n");
        }

        if (!hasModule) {
            host.diagnostics.debugLog("  chrome.dll not found in this process.\n");
            host.diagnostics.debugLog("  This command only works in renderer processes.\n");
            host.diagnostics.debugLog("  Use !procs to list processes and |<id>s to switch.\n\n");
            return "";
        }

        var xOutput;
        try {
            xOutput = ctl.ExecuteCommand("x chrome!*g_frame_map*");
        } catch (xErr) {
            host.diagnostics.debugLog("  Symbol lookup failed: " + (xErr.message || xErr) + "\n");
            host.diagnostics.debugLog("  Try: .reload /f chrome.dll\n\n");
            return "";
        }

        var lazyInstanceAddr = null;

        for (var line of xOutput) {
            var lineStr = line.toString();
            host.diagnostics.debugLog("    > " + lineStr + "\n");
            var match = lineStr.match(/^([0-9a-fA-F`]+)/);
            if (match) {
                lazyInstanceAddr = match[1].replace(/`/g, "");
                break;
            }
        }

        if (!lazyInstanceAddr) {
            host.diagnostics.debugLog("  Could not find g_frame_map symbol.\n");
            host.diagnostics.debugLog("  Make sure symbols are loaded (try: .reload /f chrome.dll)\n\n");
            return "";
        }

        host.diagnostics.debugLog("  g_frame_map (LazyInstance) at: 0x" + lazyInstanceAddr + "\n");

        // LazyInstance has private_instance_ as first member (std::atomic<uintptr_t>)
        // This holds the pointer to the actual FrameMap once initialized
        // Read the pointer value from the LazyInstance
        host.diagnostics.debugLog("  Step 2: Reading private_instance_ pointer...\n");
        var mapAddr = null;
        try {
            var lazyAddrVal = BigInt("0x" + lazyInstanceAddr);
            var ptrValue = host.memory.readMemoryValues(host.parseInt64(lazyAddrVal.toString(16), 16), 1, 8)[0];
            mapAddr = ptrValue.toString(16);
        } catch (e) { }

        if (!mapAddr || mapAddr === "0000000000000000" || mapAddr === "00000000") {
            host.diagnostics.debugLog("  LazyInstance not yet initialized (no frames created yet).\n\n");
            return "";
        }

        host.diagnostics.debugLog("  FrameMap (actual map) at: 0x" + mapAddr + "\n\n");

        // Now enumerate the flat_hash_map
        // absl::flat_hash_map uses Swiss tables internally
        // Try using dx with the FrameMap type
        host.diagnostics.debugLog("  Enumerating frames...\n");
        host.diagnostics.debugLog("  " + "-".repeat(70) + "\n\n");

        var frames = [];
        var currentWebFrame = null;

        // Use dx with moderate recursion to see the map entries
        var dxCmd = "dx -r5 *((content::`anonymous namespace'::FrameMap*)0x" + mapAddr + ")";
        var mapOutput = ctl.ExecuteCommand(dxCmd);

        for (var line of mapOutput) {
            var lineStr = line.toString();

            // Look for "first" entries (WebFrame pointers)
            // Pattern: "first : 0x... [Type: blink::WebFrame *]"
            var firstMatch = lineStr.match(/first\s*:\s*(0x[0-9a-fA-F`]+)\s*\[Type:\s*blink::WebFrame/i);
            if (firstMatch) {
                currentWebFrame = firstMatch[1].replace(/`/g, "");
            }

            // Look for "second" entries (RenderFrameImpl pointers)
            // Pattern: "second : 0x... [Type: content::RenderFrameImpl *]"
            var secondMatch = lineStr.match(/second\s*:\s*(0x[0-9a-fA-F`]+)\s*\[Type:\s*content::RenderFrameImpl/i);
            if (secondMatch && currentWebFrame) {
                frames.push({
                    webFrame: currentWebFrame,
                    renderFrame: secondMatch[1].replace(/`/g, "")
                });
                currentWebFrame = null;
            }
        }

        // Display the frames
        if (frames.length > 0) {
            host.diagnostics.debugLog("  Found " + frames.length + " frame(s):\n\n");

            // Get the Oilpan cage base for pointer decompression
            var oilpanBase = getCppgcCageBase();
            if (oilpanBase) {
                host.diagnostics.debugLog("  (Oilpan Cage Base: 0x" + oilpanBase + ")\n\n");
            }

            for (var i = 0; i < frames.length; i++) {
                var f = frames[i];
                var rfId = "N/A"; // Initialize rfId

                // Extract process_label_id_ from RenderFrameImpl
                if (f.renderFrame) {
                    try {
                        var rfCmd = "dx -r0 ((content::RenderFrameImpl*)" + f.renderFrame + ")->process_label_id_";
                        // host.diagnostics.debugLog("Debug RF: " + rfCmd + "\n");
                        var rfOutput = ctl.ExecuteCommand(rfCmd);
                        for (var rfLine of rfOutput) {
                            // host.diagnostics.debugLog("Debug RF line: " + rfLine.toString() + "\n");
                            if (rfLine.toString().indexOf("process_label_id_") !== -1) {
                                var idMatch = rfLine.toString().match(/:\s*(\d+)/);
                                if (idMatch) {
                                    rfId = idMatch[1];
                                    break;
                                }
                            }
                        }
                    } catch (eRf) {
                        // host.diagnostics.debugLog("Debug RF Error: " + eRf.message + "\n");
                    }
                }

                host.diagnostics.debugLog("  [" + i + "] RenderFrameImpl:  " + f.renderFrame + " (ID: " + rfId + ")\n");
                host.diagnostics.debugLog("       WebFrame:         " + f.webFrame + "\n");

                // Try to get LocalFrame by decompressing the compressed pointer at WebLocalFrameImpl+0x3c
                var localFrameAddr = null;
                var urlStr = "";

                try {
                    // Read the compressed pointer at offset +0x3c (frame_)
                    var webFrameVal = BigInt(f.webFrame.startsWith("0x") ? f.webFrame : "0x" + f.webFrame);
                    var offset = webFrameVal + 0x3cn;
                    var offsetInt64 = host.parseInt64(offset.toString(16), 16);

                    var compressedPtr = host.memory.readMemoryValues(offsetInt64, 1, 4)[0];

                    // Decompress using Oilpan formula
                    localFrameAddr = decompressCppgcPtr(compressedPtr, f.webFrame);
                    if (localFrameAddr) {
                        host.diagnostics.debugLog("       LocalFrame:       0x" + localFrameAddr + "\n");
                    }
                } catch (e1) { }

                // Trace URL: LocalFrame -> loader_ (FrameLoader) -> document_loader_ (DocumentLoader) -> url_
                if (localFrameAddr) {
                    try {
                        // Offset of loader_ in LocalFrame (0x1c8 based on dx output)
                        // Offset of document_loader_ in FrameLoader (0x10 based on dx output)
                        // Total offset: 0x1d8
                        var docLoaderPtrOffsetBig = BigInt("0x" + localFrameAddr) + 0x1d8n;
                        var docLoaderPtrOffset = host.parseInt64(docLoaderPtrOffsetBig.toString(16), 16);

                        // Read Compressed ptr
                        var docLoaderCompressed = host.memory.readMemoryValues(docLoaderPtrOffset, 1, 4)[0];

                        // Decompress (using LocalFrame as context, they are in same heap)
                        var docLoaderAddr = decompressCppgcPtr(docLoaderCompressed, localFrameAddr);

                        // host.diagnostics.debugLog("Debug: DocLoaderAddr: 0x" + docLoaderAddr.toString(16) + "\n");

                        if (docLoaderAddr) {
                            // Use dx to extract the URL string from DocumentLoader
                            // We target url_.string_ directly to get the data
                            var dxCmd = "dx -r2 ((blink::DocumentLoader*)0x" + docLoaderAddr.toString(16) + ")->url_.string_";
                            var output = ctl.ExecuteCommand(dxCmd);
                            for (var line of output) {
                                var sLine = line.toString();
                                // host.diagnostics.debugLog("Debug dx: " + sLine + "\n");

                                // Match AsciiText line: Debug dx: AsciiText : 0x... : "https://..." [Type: char *]
                                if (sLine.indexOf("AsciiText") !== -1) {
                                    var m = sLine.match(/"(.*)"/);
                                    if (m) {
                                        urlStr = m[1];
                                        break;
                                    }
                                }
                            }
                        }
                    } catch (eUrl) {
                        host.diagnostics.debugLog("       (URL Error: " + eUrl.message + ")\n");
                    }
                }

                if (urlStr) {
                    host.diagnostics.debugLog("       URL:              " + urlStr + "\n");
                } else {
                    host.diagnostics.debugLog("       URL:              (use dx to inspect)\n");
                }
                host.diagnostics.debugLog("\n");
            }
        } else {
            host.diagnostics.debugLog("  No frames found. Map may be empty.\n\n");
            host.diagnostics.debugLog("  Manual inspection commands:\n");
            host.diagnostics.debugLog("    dq 0x" + mapAddr + " L10\n");
            host.diagnostics.debugLog("    dx *((content::`anonymous namespace'::FrameMap*)0x" + mapAddr + ")\n\n");
        }

        host.diagnostics.debugLog("\n  Useful commands:\n");
        host.diagnostics.debugLog("    dx ((content::RenderFrameImpl*)<addr>)         - Inspect RenderFrameImpl\n");
        host.diagnostics.debugLog("    dx ((content::RenderFrameImpl*)<addr>)->frame_ - Get WebLocalFrame\n");
        host.diagnostics.debugLog("    dx ((blink::WebLocalFrame*)<addr>)             - Inspect WebFrame\n\n");

    } catch (e) {
        host.diagnostics.debugLog("  Error: " + (e.message || e.toString()) + "\n");
        if (e.stack) {
            host.diagnostics.debugLog("  Stack: " + e.stack + "\n");
        }
        host.diagnostics.debugLog("\n  Manual approach:\n");
        host.diagnostics.debugLog("    x chrome!*g_frame_map*\n");
        host.diagnostics.debugLog("    dq <addr> L1                ; Read LazyInstance.private_instance_\n");
        host.diagnostics.debugLog("    dx *((content::`anonymous namespace'::FrameMap*)<ptr>)\n\n");
    }

    return "";
}




/// Execute a command only in renderer processes (works from any process context)
function run_in_renderer(command) {
    if (!command) {
        host.diagnostics.debugLog("\n=== Run in Renderer ===\n\n");
        host.diagnostics.debugLog("  Usage: !run_in_renderer \"<windbg command>\"\n");
        host.diagnostics.debugLog("  Example: !run_in_renderer \"bp chrome!v8::internal::Heap::CollectGarbage\"\n\n");
        host.diagnostics.debugLog("  Works from ANY process - automatically finds and runs in all renderers.\n\n");
        return "";
    }
    return runInProcessType("renderer", command);
}

/// Execute a command only in browser process (works from any process context)
function run_in_browser(command) {
    if (!command) {
        host.diagnostics.debugLog("\n=== Run in Browser ===\n\n");
        host.diagnostics.debugLog("  Usage: !run_in_browser \"<windbg command>\"\n");
        host.diagnostics.debugLog("  Example: !run_in_browser \"bp chrome!Browser::Create\"\n\n");
        host.diagnostics.debugLog("  Works from ANY process - automatically finds and runs in browser.\n\n");
        return "";
    }
    return runInProcessType("browser", command);
}

/// Execute a command only in GPU process (works from any process context)
function run_in_gpu(command) {
    if (!command) {
        host.diagnostics.debugLog("\n=== Run in GPU ===\n\n");
        host.diagnostics.debugLog("  Usage: !run_in_gpu \"<windbg command>\"\n");
        host.diagnostics.debugLog("  Example: !run_in_gpu \"bp chrome!gpu::CommandBufferService::Flush\"\n\n");
        host.diagnostics.debugLog("  Works from ANY process - automatically finds and runs in GPU process.\n\n");
        return "";
    }
    return runInProcessType("gpu", command);
}


/// Set up commands to run automatically when a renderer process attaches
function on_renderer_attach(command) {
    host.diagnostics.debugLog("\n=== Renderer Auto-Attach Setup ===\n\n");

    if (!command) {
        host.diagnostics.debugLog("  This sets up commands to run when new renderer processes attach.\n\n");
        host.diagnostics.debugLog("  Usage: !on_renderer_attach \"<windbg command>\"\n\n");
        host.diagnostics.debugLog("  Examples:\n");
        host.diagnostics.debugLog("    !on_renderer_attach \"!sandbox_state\"\n");
        host.diagnostics.debugLog("    !on_renderer_attach \"bp chrome!blink::Document::CreateRawElement\"\n");
        host.diagnostics.debugLog("    !on_renderer_attach \".echo Renderer attached!\"\n\n");
        host.diagnostics.debugLog("  Registered commands:\n");
        host.diagnostics.debugLog("  " + "-".repeat(40) + "\n");
        for (var i = 0; i < g_rendererAttachCommands.length; i++) {
            host.diagnostics.debugLog("    " + (i + 1) + ": " + g_rendererAttachCommands[i] + "\n");
        }
        if (g_rendererAttachCommands.length === 0) {
            host.diagnostics.debugLog("    (none)\n");
        }
        host.diagnostics.debugLog("\n  TIP: To trigger on child process creation, use WinDbg:\n");
        host.diagnostics.debugLog("    sxe -c \"!run_in_renderer \\\"<cmd>\\\"\" cpr\n\n");
        return "";
    }

    g_rendererAttachCommands.push(command);
    host.diagnostics.debugLog("  Added: " + command + "\n");
    host.diagnostics.debugLog("  Total registered commands: " + g_rendererAttachCommands.length + "\n\n");

    // Set up child process creation event to run our commands
    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        // Use sxe cpr (create process) to catch child process creation
        var handlerCmd = "sxe -c \"!run_in_renderer \\\"" + command.replace(/"/g, "'") + "\\\"; g\" cpr";
        host.diagnostics.debugLog("  Setting up: " + handlerCmd + "\n");
        ctl.ExecuteCommand(handlerCmd);

        host.diagnostics.debugLog("\n  Handler registered. Command will run in new renderer processes.\n\n");
    } catch (e) {
        host.diagnostics.debugLog("  Note: Auto-setup failed. Manually use:\n");
        host.diagnostics.debugLog("    sxe -c \"!run_in_renderer \\\"" + command + "\\\"; g\" cpr\n\n");
    }

    return "";
}

/// Execute a script file only in renderer processes (works from any process context)
function run_script_in_renderer(scriptPath) {
    if (!scriptPath) {
        host.diagnostics.debugLog("\n=== Run Script in Renderer ===\n\n");
        host.diagnostics.debugLog("  Usage: !run_script_in_renderer \"<path to .js script>\"\n\n");
        host.diagnostics.debugLog("  Examples:\n");
        host.diagnostics.debugLog("    !run_script_in_renderer \"C:\\scripts\\renderer_hooks.js\"\n");
        host.diagnostics.debugLog("    !run_script_in_renderer \"renderer_security.js\"\n\n");
        host.diagnostics.debugLog("  Works from ANY process - automatically loads in all renderers.\n\n");
        return "";
    }

    // Reuse run_in_renderer to handle process iteration
    var loadCmd = ".scriptload " + scriptPath;
    return run_in_renderer(loadCmd);
}

/// Set up a script to load automatically when renderer processes attach
function script_in_renderer_attach(scriptPath) {
    host.diagnostics.debugLog("\n=== Script Auto-Load on Renderer Attach ===\n\n");

    if (!scriptPath) {
        host.diagnostics.debugLog("  Usage: !script_in_renderer_attach \"<path to .js script>\"\n\n");
        host.diagnostics.debugLog("  This will auto-load the script when new renderer processes spawn.\n\n");
        host.diagnostics.debugLog("  Examples:\n");
        host.diagnostics.debugLog("    !script_in_renderer_attach \"renderer_hooks.js\"\n");
        host.diagnostics.debugLog("    !script_in_renderer_attach \"C:\\research\\exploit_test.js\"\n\n");
        return "";
    }

    host.diagnostics.debugLog("  Registering: " + scriptPath + "\n\n");

    // Set up child process creation event to load the script
    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        // The handler checks if it's a renderer and loads the script
        var handlerCmd = "sxe -c \"!run_script_in_renderer \\\"" + scriptPath.replace(/\\/g, "\\\\").replace(/"/g, "'") + "\\\"; g\" cpr";
        host.diagnostics.debugLog("  Setting up: " + handlerCmd + "\n");
        ctl.ExecuteCommand(handlerCmd);

        host.diagnostics.debugLog("\n  Handler registered!\n");
        host.diagnostics.debugLog("  Script will load automatically in new renderer processes.\n\n");
    } catch (e) {
        host.diagnostics.debugLog("  Note: Auto-setup failed. Manually use:\n");
        host.diagnostics.debugLog("    sxe -c \"!run_script_in_renderer \\\"" + scriptPath + "\\\"; g\" cpr\n\n");
    }

    return "";
}

/// =============================================================================
/// SECURITY RESEARCH BREAKPOINTS
/// =============================================================================

/// Break on mojo::ReportBadMessage - catches security boundary violations
function bp_bad_message() {
    host.diagnostics.debugLog("\n=== Bad Message Breakpoints (Security Violations) ===\n\n");
    host.diagnostics.debugLog("  These breakpoints catch Mojo security violations.\n");
    host.diagnostics.debugLog("  When hit, check the message string for the violation reason.\n\n");

    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        // Core mojo bad message reporting
        var bpTargets = [
            "mojo!mojo::ReportBadMessage",
            "mojo_base!mojo::ReportBadMessage",
            "content!mojo::ReportBadMessage"
        ];

        for (var i = 0; i < bpTargets.length; i++) {
            host.diagnostics.debugLog("  Setting: bp " + bpTargets[i] + "\n");
            try {
                ctl.ExecuteCommand("bp " + bpTargets[i]);
            } catch (e) {
                // Symbol may not exist
            }
        }

        host.diagnostics.debugLog("\n  Common violations to look for:\n");
        host.diagnostics.debugLog("  " + "-".repeat(50) + "\n");
        host.diagnostics.debugLog("    - 'File System Access access from Unsecure Origin'\n");
        host.diagnostics.debugLog("    - 'navigate from non-browser-process'\n");
        host.diagnostics.debugLog("    - 'Received bad user message'\n");
        host.diagnostics.debugLog("    - 'Invalid origin'\n");
        host.diagnostics.debugLog("\n  When breakpoint hits, use: da @rcx (or first param) to see message\n\n");

    } catch (e) {
        host.diagnostics.debugLog("  Error: " + e.message + "\n");
    }

    return "";
}

/// Break on security policy checks
function bp_security_check() {
    host.diagnostics.debugLog("\n=== Security Policy Breakpoints ===\n\n");
    host.diagnostics.debugLog("  These breakpoints catch security policy decisions.\n\n");

    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        var bpTargets = [
            // Process lock and origin checks
            { sym: "content!ChildProcessSecurityPolicyImpl::CanAccessDataForOrigin", desc: "Origin access check" },
            { sym: "content!ChildProcessSecurityPolicyImpl::CanCommitURL", desc: "URL commit check" },
            { sym: "content!ChildProcessSecurityPolicyImpl::GetProcessLock", desc: "Process lock query" },
            // Site isolation
            { sym: "content!SiteIsolationPolicy::UseDedicatedProcessesForAllSites", desc: "Site isolation check" },
            { sym: "content!SiteInstanceImpl::GetProcess", desc: "SiteInstance process" },
            // Sandbox
            { sym: "sandbox!TargetServicesBase::LowerToken", desc: "Sandbox token lowering" }
        ];

        for (var i = 0; i < bpTargets.length; i++) {
            var target = bpTargets[i];
            host.diagnostics.debugLog("  [" + target.desc + "]\n");
            host.diagnostics.debugLog("    bp " + target.sym + "\n");
            try {
                ctl.ExecuteCommand("bp " + target.sym);
            } catch (e) {
                host.diagnostics.debugLog("    (symbol not found)\n");
            }
        }

        host.diagnostics.debugLog("\n  Breakpoints set. Use 'bl' to list, 'bc *' to clear.\n\n");

    } catch (e) {
        host.diagnostics.debugLog("  Error: " + e.message + "\n");
    }

    return "";
}

/// Enable IPC/Mojo message tracing
function trace_ipc() {
    host.diagnostics.debugLog("\n=== IPC Tracing Mode ===\n\n");
    host.diagnostics.debugLog("  Setting breakpoints to log IPC traffic.\n");
    host.diagnostics.debugLog("  WARNING: This can be very noisy!\n\n");

    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        // Mojo message dispatch points
        var bpTargets = [
            { sym: "mojo!mojo::MessageDispatcher::Accept", desc: "Mojo message accept" },
            { sym: "content!BrowserInterfaceBrokerImpl::GetInterface", desc: "Interface broker" },
            { sym: "ipc!IPC::ChannelMojo::OnMessageReceived", desc: "Legacy IPC receive" }
        ];

        for (var i = 0; i < bpTargets.length; i++) {
            var target = bpTargets[i];
            // Set logging breakpoint that continues
            var cmd = 'bp ' + target.sym + ' ".echo [IPC] ' + target.desc + '; k 3; g"';
            host.diagnostics.debugLog("  " + target.desc + ":\n");
            host.diagnostics.debugLog("    " + cmd + "\n");
            try {
                ctl.ExecuteCommand(cmd);
            } catch (e) {
                host.diagnostics.debugLog("    (symbol not found)\n");
            }
        }

        host.diagnostics.debugLog("\n  Tracing enabled. IPC calls will be logged with short stacks.\n");
        host.diagnostics.debugLog("  Use 'bc *' to clear all breakpoints when done.\n\n");

    } catch (e) {
        host.diagnostics.debugLog("  Error: " + e.message + "\n");
    }

    return "";
}

/// =============================================================================
/// VULNERABILITY HUNTING
/// =============================================================================

/// Set breakpoints for common vulnerability patterns
function vuln_hunt() {
    host.diagnostics.debugLog("\n=== Vulnerability Hunting Mode ===\n\n");
    host.diagnostics.debugLog("  Setting breakpoints for common vulnerability patterns.\n\n");

    try {
        var ctl = host.namespace.Debugger.Utility.Control;

        var categories = [
            {
                name: "Use-After-Free Indicators",
                targets: [
                    { sym: "ntdll!RtlFreeHeap", desc: "Heap free (watch for double-free)" },
                    { sym: "chrome!base::PartitionFree", desc: "PartitionAlloc free" },
                    { sym: "chrome!content::RenderProcessHostImpl::Cleanup", desc: "Renderer cleanup" }
                ]
            },
            {
                name: "Type Confusion Points",
                targets: [
                    { sym: "chrome!blink::V8ScriptValueDeserializer::Deserialize", desc: "Deserialization" },
                    { sym: "chrome!v8::internal::Object::ToObject", desc: "V8 type coercion" }
                ]
            },
            {
                name: "Race Condition Hotspots",
                targets: [
                    { sym: "chrome!content::ChildProcessHost::OnMessageReceived", desc: "IPC receive (browser)" },
                    { sym: "chrome!content::ChildThreadImpl::OnMessageReceived", desc: "IPC receive (renderer)" }
                ]
            },
            {
                name: "Memory Corruption Detectors",
                targets: [
                    { sym: "chrome!base::debug::BreakDebugger", desc: "Debug break (crash)" },
                    { sym: "chrome!base::debug::CollectStackTrace", desc: "Stack trace (crash path)" }
                ]
            }
        ];

        for (var c = 0; c < categories.length; c++) {
            var cat = categories[c];
            host.diagnostics.debugLog("  " + cat.name + ":\n");
            host.diagnostics.debugLog("  " + "-".repeat(50) + "\n");

            for (var i = 0; i < cat.targets.length; i++) {
                var target = cat.targets[i];
                host.diagnostics.debugLog("    [" + target.desc + "]\n");
                host.diagnostics.debugLog("      bp " + target.sym + "\n");
                try {
                    ctl.ExecuteCommand("bp " + target.sym);
                } catch (e) { }
            }
            host.diagnostics.debugLog("\n");
        }

        host.diagnostics.debugLog("  Breakpoints set. Use 'bl' to list, 'bc *' to clear.\n\n");

    } catch (e) {
        host.diagnostics.debugLog("  Error: " + e.message + "\n");
    }

    return "";
}

/// Display heap/allocator information
function heap_info() {
    host.diagnostics.debugLog("\n=== Heap / PartitionAlloc Info ===\n\n");

    try {
        var ctl = host.namespace.Debugger.Utility.Control;
        var procType = getProcessType();

        host.diagnostics.debugLog("  Process Type: " + procType + "\n\n");

        host.diagnostics.debugLog("  PartitionAlloc Structures:\n");
        host.diagnostics.debugLog("  " + "-".repeat(50) + "\n");
        host.diagnostics.debugLog("    dt chrome!base::PartitionRoot\n");
        host.diagnostics.debugLog("    dt chrome!base::internal::SlotSpanMetadata\n");
        host.diagnostics.debugLog("    dt chrome!base::PartitionRoot\n\n");

        host.diagnostics.debugLog("  Useful Commands:\n");
        host.diagnostics.debugLog("  " + "-".repeat(50) + "\n");
        host.diagnostics.debugLog("    !heap -s                           - NT heap summary\n");
        host.diagnostics.debugLog("    !heap -a <addr>                    - Analyze heap address\n");
        host.diagnostics.debugLog("    dps <addr> L10                     - Dump pointers at address\n");
        host.diagnostics.debugLog("    !address <addr>                    - Memory region info\n\n");

        host.diagnostics.debugLog("  PartitionAlloc Breakpoints:\n");
        host.diagnostics.debugLog("  " + "-".repeat(50) + "\n");

        var paTargets = [
            "base::PartitionRoot::Alloc",
            "base::PartitionRoot::Free",
            "base::internal::PartitionBucket::SlowPathAlloc"
        ];

        for (var i = 0; i < paTargets.length; i++) {
            var sym = "chrome!" + paTargets[i];
            host.diagnostics.debugLog("    bp " + sym + "\n");
        }

        host.diagnostics.debugLog("\n  V8 Heap (renderer only):\n");
        host.diagnostics.debugLog("  " + "-".repeat(50) + "\n");
        host.diagnostics.debugLog("    dt chrome!v8::internal::Heap\n");
        host.diagnostics.debugLog("    bp chrome!v8::internal::Heap::CollectGarbage\n\n");

    } catch (e) {
        host.diagnostics.debugLog("  Error: " + e.message + "\n");
    }

    return "";
}

/// =============================================================================
/// BLINK HOOKS
/// =============================================================================

function blink_help() {
    host.diagnostics.debugLog(`
=== Blink DOM Security Hooks ===

  !bp_element   - Break on DOM element creation
  !bp_nav       - Break on navigation/location changes  
  !bp_pm        - Break on postMessage (cross-origin comms)
  !bp_fetch     - Break on fetch/XHR requests

  Target symbols (chrome.dll):
    blink::Document::CreateRawElement
    blink::LocalDOMWindow::postMessage
    blink::FetchManager::Fetch
    
`);
    return "";
}

function bp_element() {
    return set_breakpoints(
        "DOM Element Creation Breakpoints",
        [
            "chrome!blink::Document::CreateRawElement",
            "chrome!blink::Document::createElement",
            "chrome!blink::HTMLElement::insertAdjacentHTML"
        ],
        "DOM clobbering, XSS sink analysis"
    );
}

function bp_nav() {
    return set_breakpoints(
        "Navigation Breakpoints",
        [
            "chrome!blink::LocalDOMWindow::setLocation",
            "chrome!blink::Location::assign",
            "chrome!blink::Location::replace",
            "chrome!blink::FrameLoader::StartNavigation"
        ],
        "Navigation hijacking, URL spoofing"
    );
}

function bp_pm() {
    return set_breakpoints(
        "postMessage Breakpoints",
        [
            "chrome!blink::LocalDOMWindow::postMessage",
            "chrome!blink::MessageEvent::Create"
        ],
        "Cross-origin message interception"
    );
}

function bp_fetch() {
    return set_breakpoints(
        "Fetch/XHR Breakpoints",
        [
            "chrome!blink::FetchManager::Fetch",
            "chrome!blink::XMLHttpRequest::send",
            "chrome!blink::XMLHttpRequest::open"
        ],
        "Request interception, CORS bypass"
    );
}

/// =============================================================================
/// V8 HOOKS
/// =============================================================================

function v8_help() {
    host.diagnostics.debugLog(`
=== V8 Exploitation Hooks ===

  !bp_compile   - Break on script compilation
  !bp_gc        - Break on garbage collection
  !bp_wasm      - Break on WebAssembly compilation  
  !bp_jit       - Break on JIT code generation

  Target module: chrome.dll (v8 is statically linked)
  
  Tips:
  - V8 symbols are large, use: .symopt+0x10 for deferred loading
  - For heap inspection: dt chrome!v8::internal::Heap
  
`);
    return "";
}

function bp_compile() {
    return set_breakpoints(
        "V8 Script Compilation Breakpoints",
        [
            "chrome!v8::Script::Compile",
            "chrome!v8::ScriptCompiler::Compile",
            "chrome!v8::internal::Compiler::Compile"
        ],
        "Analyzing JIT compilation, CSP bypass"
    );
}

function bp_gc() {
    return set_breakpoints(
        "V8 Garbage Collection Breakpoints",
        [
            "chrome!v8::internal::Heap::CollectGarbage",
            "chrome!v8::internal::Heap::PerformGarbageCollection",
            "chrome!v8::internal::MarkCompactCollector::CollectGarbage"
        ],
        "UAF exploitation, heap grooming"
    );
}

function bp_wasm() {
    return set_breakpoints(
        "WebAssembly Breakpoints",
        [
            "chrome!v8::internal::wasm::CompileLazy",
            "chrome!v8::internal::wasm::WasmEngine::SyncCompile",
            "chrome!v8::internal::wasm::WasmCodeManager::Commit"
        ],
        "WASM JIT bugs, RWX page analysis"
    );
}

function bp_jit() {
    return set_breakpoints(
        "V8 JIT Code Generation Breakpoints",
        [
            "chrome!v8::internal::compiler::PipelineImpl::GenerateCode",
            "chrome!v8::internal::Builtins::Generate_*",
            "chrome!v8::internal::MacroAssembler::Call"
        ],
        "JIT spray, code injection analysis"
    );
}

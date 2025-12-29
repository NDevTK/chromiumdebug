/// =============================================================================
/// Chromium Security Research WinDbg Script
/// =============================================================================
/// A comprehensive debugging toolkit for Chromium security research.
/// Load this script with: .scriptload chromium_security.js
/// =============================================================================

"use strict";

/// Global state
var g_rendererAttachCommands = [];
var g_spoofMap = new Map(); // Map<ClientId, {currentUrl: string, pid: number}>
var g_exitHandlerRegistered = false;

/// Constants
const DEBUG_MODE = false; // Set to true to enable verbose error logging
const MAX_PATCHES = 50;
const MAX_CALLER_DISPLAY = 3;
const BROWSER_CMDLINE_MIN_LENGTH = 500;
const USER_MODE_ADDR_LIMIT = "0x7fffffffffff";
const MIN_PTR_VALUE_LENGTH = 4;
const MAX_DOM_TRAVERSAL_NODES = 5000;
const STRINGIMPL_DATA_OFFSET = 12; // Offset from StringImpl to character data
const MAX_URL_STRING_LENGTH = 10000; // Maximum reasonable URL length for validation
const MAX_BACKWARD_SCAN_BYTES = 1536; // 1.5KB backward scan limit for vtable detection
const MAX_INTEGRITY_DISPLAY_LENGTH = 25; // Truncation length for integrity level display
const CMDLINE_DISPLAY_LENGTH = 200; // Truncation length for command line display
const ELEMENT_DATA_UNIQUE_FLAG = 0x1; // Bit 0 indicates UniqueElementData vs ShareableElementData
const ELEMENT_DATA_ARRAY_SIZE_MASK = 0xFFFFFFF; // Bits 1-28 contain array size
const MIN_VALID_VTABLE_ADDR = 0x10000; // Minimum valid address for vtable pointer validation
const MAX_CACHE_SIZE_PER_PID = 1000; // Maximum number of symbols to cache per PID to prevent leaks
const MAX_PID_CACHE_SIZE = 10; // Maximum number of PIDs to track to prevent memory leaks

/// Helper: Check if string is empty or null
function isEmpty(str) {
    return !str || str === "";
}

/// Helper: Parse integer from string, auto-detecting hex (0x prefix) or decimal
function parseIntAuto(str) {
    if (!str) return 0;
    var s = str.toString().trim();
    return s.startsWith("0x") || s.startsWith("0X") ? parseInt(s, 16) : parseInt(s, 10);
}

/// Helper: Check if a BigInt value is a valid user-mode pointer
/// @param val - BigInt value to check
/// @returns true if val is within valid user-mode address range (0x10000 < val < 0x7fffffffffff)
function isValidUserModePointer(val) {
    if (typeof val !== "bigint") return false;
    return val > BigInt(MIN_VALID_VTABLE_ADDR) && val < BigInt(USER_MODE_ADDR_LIMIT);
}

/// Helper: Register sxe cpr handler for renderer attach
function _registerRendererSxeHandler(commandString, displayLabel) {
    try {
        var ctl = SymbolUtils.getControl();
        // Escape quotes for nesting
        var escapedCmd = commandString.replace(/"/g, "'");
        var handlerCmd = "sxe -c \"" + escapedCmd + "; g\" cpr";
        Logger.info("  Setting up: " + handlerCmd);
        ctl.ExecuteCommand(handlerCmd);
        Logger.empty();
        Logger.info("  Handler registered. " + (displayLabel || "Command") + " will run in new renderer processes.");
        Logger.empty();
    } catch (e) {
        Logger.warn("Note: Auto-setup failed. Manually use sxe command.");
        Logger.empty();
    }
}

/// =============================================================================
/// GLOBAL CACHE
/// =============================================================================

class GlobalCache {
    // Map<PID, Map<Key, Value>>
    static _symbolCache = new Map();
    static _reverseSymbolCache = new Map();
    static _v8CageBaseCache = new Map(); // Map<PID, AddressString>
    static _cppgcCageBaseCache = new Map(); // Map<PID, AddressString>

    static _getPid() {
        try {
            var pid = parseInt(host.currentProcess.Id);
            // Safety: Avoid caching for PID 0 (System) or invalid PIDs
            if (pid === 0 || isNaN(pid)) return null;
            return pid;
        } catch (e) { return null; }
    }

    // Generic LRU Get: returns value or undefined, moves to end if found
    static _getLru(map, key) {
        if (map && map.has(key)) {
            const val = map.get(key);
            map.delete(key);
            map.set(key, val);
            return val;
        }
        return undefined;
    }

    // Generic LRU Set: sets value, moves to end, enforces size limit
    static _setLru(map, key, value, maxSize) {
        if (!map) return;
        if (map.has(key)) {
            map.delete(key);
        } else if (map.size >= maxSize) {
            const oldest = map.keys().next().value;
            map.delete(oldest);
        }
        map.set(key, value);
    }

    // Helper: Ensure a PID cache exists in the given map, creating if needed
    static _ensurePidCache(cacheMap, pid) {
        if (!cacheMap.has(pid)) {
            // Enforce PID cache limit before adding new entry
            if (cacheMap.size >= MAX_PID_CACHE_SIZE) {
                const oldest = cacheMap.keys().next().value;
                cacheMap.delete(oldest);
            }
            cacheMap.set(pid, new Map());
        }
        return cacheMap.get(pid);
    }

    static getSymbol(symbolName) {
        var pid = this._getPid();
        if (!pid) return undefined;
        var pidCache = this._getLru(this._symbolCache, pid);
        return pidCache ? this._getLru(pidCache, symbolName) : undefined;
    }

    static setSymbol(symbolName, address) {
        var pid = this._getPid();
        if (!pid) return;

        var pidCache = this._ensurePidCache(this._symbolCache, pid);
        this._setLru(pidCache, symbolName, address, MAX_CACHE_SIZE_PER_PID);
    }

    static getSymbolName(address) {
        var pid = this._getPid();
        if (!pid) return undefined;
        var pidCache = this._getLru(this._reverseSymbolCache, pid);
        return pidCache ? this._getLru(pidCache, address) : undefined;
    }

    static setSymbolName(address, name) {
        var pid = this._getPid();
        if (!pid) return;

        var pidCache = this._ensurePidCache(this._reverseSymbolCache, pid);
        this._setLru(pidCache, address, name, MAX_CACHE_SIZE_PER_PID);
    }

    static getV8Cage() {
        var pid = this._getPid();
        if (!pid) return undefined;
        return this._getLru(this._v8CageBaseCache, pid);
    }

    static setV8Cage(address) {
        var pid = this._getPid();
        if (!pid) return;
        this._setLru(this._v8CageBaseCache, pid, address, MAX_PID_CACHE_SIZE);
    }

    static getCppgcCage() {
        var pid = this._getPid();
        if (!pid) return undefined;
        return this._getLru(this._cppgcCageBaseCache, pid);
    }

    static setCppgcCage(address) {
        var pid = this._getPid();
        if (!pid) return;
        this._setLru(this._cppgcCageBaseCache, pid, address, MAX_PID_CACHE_SIZE);
    }

    static clearCurrent() {
        var pid = this._getPid();
        if (pid) this.clearPid(pid);
    }

    static clearPid(pid) {
        this._symbolCache.delete(pid);
        this._reverseSymbolCache.delete(pid);
        this._v8CageBaseCache.delete(pid);
        this._cppgcCageBaseCache.delete(pid);
    }

    static clearAll() {
        this._symbolCache.clear();
        this._reverseSymbolCache.clear();
        this._v8CageBaseCache.clear();
        this._cppgcCageBaseCache.clear();
    }
}

/// =============================================================================
/// UTILITIES & CLASSES
/// =============================================================================

class Logger {
    static log(msg) { host.diagnostics.debugLog(msg); }
    static empty() { host.diagnostics.debugLog("\n"); }

    static section(title) {
        this.log("\n=== " + title + " ===\n\n");
    }

    static header(title) {
        this.log("  " + title + "\n");
        this.log("  " + "-".repeat(Math.max(40, title.length)) + "\n");
    }

    static info(msg, indent = 2) {
        this.log(" ".repeat(indent) + msg + "\n");
    }

    static warn(msg) {
        this.log("  [WARNING] " + msg + "\n\n");
    }

    static error(msg) {
        this.log("  [ERROR] " + msg + "\n\n");
    }

    /// Debug output - only logs when DEBUG_MODE is true
    static debug(msg) {
        if (DEBUG_MODE) {
            this.log("  [DEBUG] " + msg + "\n");
        }
    }

    static separator(width = 40) {
        this.log("  " + "-".repeat(width) + "\n");
    }

    static showUsage(title, usage, examples) {
        this.section(title);
        this.info("Usage: " + usage);
        this.empty();
        if (examples && examples.length > 0) {
            this.info("Examples:");
            for (var i = 0; i < examples.length; i++) {
                this.info("  " + examples[i]);
            }
            this.empty();
        }
    }

    /// Display filtered command line switches
    static displaySwitches(switches, filterList) {
        for (var i = 0; i < switches.length; i++) {
            if (filterList.indexOf(switches[i].name) !== -1) {
                var val = switches[i].value ? ("=" + switches[i].value) : "";
                this.info("  --" + switches[i].name + val);
            }
        }
    }
}

class SymbolUtils {
    static getControl() { return host.namespace.Debugger.Utility.Control; }

    /// Extract hex address from a line of debugger output (removes backticks)
    static extractAddress(line) {
        var match = line.toString().match(/^([0-9a-fA-F`]+)/);
        return match ? match[1].replace(/`/g, "") : null;
    }

    static findSymbolAddress(pattern) {
        // Only cache exact symbol matches, not patterns with wildcards
        var isExact = pattern.indexOf("*") === -1 && pattern.indexOf("?") === -1;

        if (isExact) {
            var cached = GlobalCache.getSymbol(pattern);
            if (cached) return cached;
        }

        try {
            var output = this.getControl().ExecuteCommand("x " + pattern);
            for (var line of output) {
                var addr = this.extractAddress(line);
                if (addr) {
                    if (isExact) GlobalCache.setSymbol(pattern, addr);
                    return addr;
                }
            }
        } catch (e) { Logger.debug("findSymbolAddress failed: " + e.message); }
        return null;
    }

    /// Execute command with fallback on error (DRY helper)
    static tryExecute(cmd, fallback = []) {
        try { return this.getControl().ExecuteCommand(cmd); } catch (e) { Logger.debug("tryExecute '" + cmd + "' failed: " + e.message); return fallback; }
    }

    static execute(cmd) {
        return this.tryExecute(cmd, []);
    }

    static evaluate(expression) {
        try {
            // Use '?' to evaluate expression
            var output = this.execute("? " + expression);
            for (var line of output) {
                var match = line.toString().match(/=\s+([0-9a-fA-F`]+)/);
                if (match) return match[1].replace(/`/g, "");
            }
        } catch (e) { Logger.debug("evaluate failed: " + e.message); }
        return null;
    }

    /// Get symbol name for a given address (using ln)
    static getSymbolName(subsysAddr, debug) {
        var hexAddr = normalizeAddress(subsysAddr);
        if (!hexAddr) return null;

        var cached = GlobalCache.getSymbolName(hexAddr);
        if (cached) return cached;

        try {
            // Use ln (list nearest) to get symbol
            var cmd = "ln " + hexAddr;
            if (debug) Logger.info("  [Debug] Running: " + cmd);

            var output = this.getControl().ExecuteCommand(cmd);
            for (var line of output) {
                var lineStr = line.toString();
                if (debug) Logger.info("  [Debug] ln output: " + lineStr);

                // Format: (00007ffc`12345678)   module!SymbolName   |  (0000...) ...
                // or:     (00007ffc`12345678)   module!SymbolName
                // Match the symbol name part, allowing . ? @ $ which appear in mangled names
                var match = lineStr.match(/\)\s+([a-zA-Z0-9_!:.?@$]+)/);
                if (match) {
                    if (debug) Logger.info("  [Debug] Matched symbol: " + match[1]);
                    GlobalCache.setSymbolName(hexAddr, match[1]);
                    return match[1];
                }
            }
        } catch (e) {
            if (debug) Logger.info("  [Debug] ln failed: " + e.message);
        }
        return null;
    }
}

class MemoryUtils {
    // Cache for cage bases
    // Now handled by GlobalCache

    /// Invalidate cached cage bases (call when switching processes)
    /// NOTE: With GlobalCache, we don't strictly *need* to invalidate on switch,
    /// but we might want to if memory layout changes dynamically (unlikely for cage bases).
    /// For now, we'll keep the method but make it a no-op or clear current PID only if requested.
    static invalidateCaches() {
        // GlobalCache handles PER-PID caching, so we don't need to wipe everything on context switch.
        // If we really want to force refresh for current process:
        // GlobalCache.clearCurrent(); 
        // But usually we don't want to lose the cache just because we listed processes.
    }

    /// Try to find cage bases (V8 and CppGC)
    static findCageBases() {
        this.getV8CageBase();
        this.getCppgcCageBase();
    }

    static readGlobalPointer(symbolName) {
        try {
            var addr = SymbolUtils.findSymbolAddress(symbolName);
            if (addr) {
                var dqOutput = SymbolUtils.execute("dq 0x" + addr + " L1");
                for (var dline of dqOutput) {
                    var dMatch = dline.toString().match(/[0-9a-fA-F`]+\s+([0-9a-fA-F`]+)/);
                    if (dMatch) return dMatch[1].replace(/`/g, "");
                }
            }
        } catch (e) { Logger.debug("readGlobalPointer failed for " + symbolName + ": " + e.message); }
        return null;
    }

    static parseBigInt(input) {
        if (typeof input === "string") {
            var ptrStr = input.replace(/`/g, "");
            return BigInt(ptrStr.startsWith("0x") ? ptrStr : "0x" + ptrStr);
        } else if (typeof input === "number") {
            // Handle JavaScript numbers - convert to unsigned hex
            if (input < 0) {
                // Negative number - convert to unsigned 32-bit
                input = input >>> 0;
            }
            return BigInt("0x" + input.toString(16));
        } else {
            // WinDbg host objects - convert to string first, then to hex
            // This handles host.Int64 and similar types
            try {
                var str = input.toString(16);
                return BigInt("0x" + str.replace(/`/g, ""));
            } catch (e) {
                // Fallback: try direct BigInt conversion
                return BigInt(input);
            }
        }
    }

    static getV8CageBase() {
        var cached = GlobalCache.getV8Cage();
        if (cached) return cached;

        var val = this.readGlobalPointer("chrome!v8::internal::MainCage::base_");
        if (val) GlobalCache.setV8Cage(val);
        return val;
    }

    static getCppgcCageBase() {
        var cached = GlobalCache.getCppgcCage();
        if (cached) return cached;

        var val = this.readGlobalPointer("chrome!cppgc::internal::CageBaseGlobal::g_base_");
        if (val) GlobalCache.setCppgcCage(val);
        return val;
    }

    static decompressV8Ptr(compressedPtr) {
        var cageBase = this.getV8CageBase();
        if (!cageBase) return null;

        var base = BigInt("0x" + cageBase);
        var compressed = this.parseBigInt(compressedPtr);

        // Sign-extend 32-bit (V8 uses signed offsets)
        if (compressed > 0x7FFFFFFFn) {
            compressed = compressed - 0x100000000n;
        }

        var fullPtr = base + compressed;
        return fullPtr.toString(16);
    }

    static decompressCppgcPtr(compressedPtr, contextAddr) {
        const kPointerCompressionShift = 3n;
        const kCageBaseMask = BigInt("0xFFFFFFFC00000000");

        var compressed = this.parseBigInt(compressedPtr);
        if (compressed === 0n) return null;

        // Mask to 32-bit unsigned value
        compressed = compressed & 0xFFFFFFFFn;

        // Shift left
        var offset = compressed << kPointerCompressionShift;

        // Get cage base from context address
        var base = 0n;
        if (contextAddr) {
            try {
                var context = BigInt(contextAddr.toString().startsWith("0x") ? contextAddr : "0x" + contextAddr);
                base = context & kCageBaseMask;
            } catch (e) { Logger.debug("Context address parse failed: " + e.message); }
        }

        if (base === 0n) {
            // Fallback to global cage base
            var cage = this.getCppgcCageBase();
            if (cage) {
                base = BigInt("0x" + cage);
            }
        }

        if (base !== 0n) {
            return (base | offset).toString(16);
        }

        return null;
    }

    /// Write bytes to memory
    static writeMemory(addr, bytes) {
        var ctl = SymbolUtils.getControl();
        var hexBytes = bytes.map(b => b.toString(16).padStart(2, '0')).join(" ");
        var cmd = "eb 0x" + addr + " " + hexBytes;
        ctl.ExecuteCommand(cmd);
    }

    /// Write a single byte (U8)
    static writeU8(addr, value) {
        this.writeMemory(addr, [value & 0xFF]);
    }

    /// Write a 32-bit integer (U32)
    static writeU32(addr, value) {
        var ctl = SymbolUtils.getControl();
        var hexVal = value.toString(16);
        var cmd = "ed 0x" + addr + " 0x" + hexVal;
        ctl.ExecuteCommand(cmd);
    }

    /// Write a 64-bit integer (U64)
    static writeU64(addr, value) {
        var ctl = SymbolUtils.getControl();
        // toString(16) works for both Number and BigInt
        var valStr = value.toString(16);
        var cmd = "eq 0x" + addr + " 0x" + valStr;
        ctl.ExecuteCommand(cmd);
    }

    /// Write string to memory (overwriting existing buffer)
    static writeStringImpl(implAddr, newString) {
        var ctl = SymbolUtils.getControl();
        var hexAddr = implAddr.toString().startsWith("0x") ? implAddr : "0x" + implAddr;

        var is8Bit = true; // Default to 8-bit (ASCII) - most strings are ASCII
        var currentLen = 0;
        var flags = 0;

        // Try raw memory read first (more reliable than dx symbols sometimes)
        // Layout assumption (x64):
        // +0: RefCount (4b)
        // +4: Length (4b)
        // +8: Hash/Flags (4b) - Bit 0 of flags (at offset +8) often indicates is_8bit
        try {
            var cmd = "dd " + hexAddr + " L4";
            var out = ctl.ExecuteCommand(cmd);
            for (var line of out) {
                var parts = line.toString().trim().split(/\s+/);
                if (parts.length >= 4) {
                    // parts[1] = RefCount, parts[2] = Length, parts[3] = Hash/Flags
                    currentLen = parseInt(parts[2], 16);
                    flags = parseInt(parts[3], 16);

                    // In WTF::StringImpl, the is_8bit flag is typically in the lower bits
                    // If bit 0 of hash_and_flags is 1, it's 8-bit
                    // This varies by Chromium version, so we check multiple patterns
                    // Low bit = 1 often means 8-bit
                    is8Bit = (flags & 1) === 1;
                }
                break;
            }
        } catch (e) { Logger.debug("writeStringImpl header read failed: " + e.message); }

        // Try dx for is8Bit if raw didn't confirm
        try {
            var cmd = "dx ((WTF::StringImpl*)" + hexAddr + ")->is8Bit()";
            var out = ctl.ExecuteCommand(cmd);
            for (var line of out) {
                var lineStr = line.toString();
                if (lineStr.includes("true") || lineStr.includes("1")) is8Bit = true;
                else if (lineStr.includes("false") || lineStr.includes("0")) is8Bit = false;
            }
        } catch (e) {
            // dx failed - rely on flags check or default
        }

        Logger.info("  String: Len=" + currentLen + " is8Bit=" + is8Bit + " (Flags=0x" + flags.toString(16) + ")");

        if (currentLen === 0) {
            Logger.warn("  [Warning] Length detected as 0. This might be empty string OR read failure.");
            // If we write to 0 length, we corrupt memory if it's not actually 0.
            // If target string is empty, we shouldn't be here (attr loop check).
            // Memory safety: Do not proceed if we can't verify the length field.
            if (newString.length > 0) {
                Logger.error("Cannot overwrite: Existing string length appears to be 0 or unreadable.");
            }
            return; // Always return when currentLen is 0 to prevent memory corruption
        }

        if (newString.length > currentLen) {
            Logger.warn("New string length (" + newString.length + ") > current capacity (" + currentLen + "). Truncating.");
            newString = newString.substring(0, currentLen);
        }

        // Data Address
        // If 64-bit, header is usually 12 bytes or 16 bytes aligned.
        // Data likely at +12 or +16.
        // dx &characters... is best.
        var dataAddr = null;

        // Try dx
        try {
            var charType = is8Bit ? "characters8" : "characters16";
            var cmd = "dx &((WTF::StringImpl*)" + hexAddr + ")->" + charType + "()[0]";
            var out = ctl.ExecuteCommand(cmd);
            for (var line of out) {
                var m = line.toString().match(/:\s*(0x[0-9a-fA-F]+)/);
                if (m) dataAddr = m[1];
            }
        } catch (e) { Logger.debug("writeStringImpl dx characters failed: " + e.message); }

        // Fallback: Assume offset 12 (packed) or 16 (aligned)
        if (!dataAddr) {
            // StringImpl is explicitly aligned?
            // Usually sizeof(StringImpl) = 12 on 32-bit (?), 16 on 64-bit (due to alignment padding after offset 12?)
            // Let's assume +12 if header is 3x4 bytes.
            // But on x64, 16 is safer guess?
            var baseInt = BigInt(hexAddr);
            // Data starts after header (RefCount:4 + Length:4 + Hash/Flags:4 = 12 bytes)
            // Use the defined constant for consistency
            dataAddr = (baseInt + BigInt(STRINGIMPL_DATA_OFFSET)).toString(16);
            Logger.warn("  [Warning] guessing data address at offset +0xC.");
        }

        // Write
        var bytes = [];
        if (is8Bit) {
            for (var i = 0; i < newString.length; i++) bytes.push(newString.charCodeAt(i));
            // Pad remainder with nulls
            while (bytes.length < currentLen) bytes.push(0);
        } else {
            // 16-bit write
            for (var i = 0; i < newString.length; i++) {
                var c = newString.charCodeAt(i);
                bytes.push(c & 0xFF);
                bytes.push((c >> 8) & 0xFF);
            }
            // Pad remainder with nulls (2 bytes per char)
            while (bytes.length < currentLen * 2) bytes.push(0);
        }
        this.writeMemory(dataAddr, bytes);

        // Update length
        // ed expects hex by default (usually), or we explicitly use 0x prefix.
        // If length is 13, toString(16) is "d".
        var lenCmd = "ed " + hexAddr + "+4 0x" + newString.length.toString(16);
        ctl.ExecuteCommand(lenCmd);

        Logger.info("Overwrote string in memory at 0x" + dataAddr + ".");
    }

    /// Allocate memory in the target process (wrapper for .dvalloc)
    static alloc(size) {
        if (!size || size <= 0) return null;
        var ctl = SymbolUtils.getControl();
        try {
            // Allocate memory (PAGE_EXECUTE_READWRITE for flexibility)
            // .dvalloc [Options] size
            var cmd = ".dvalloc " + size;
            var output = ctl.ExecuteCommand(cmd);
            for (var line of output) {
                // Output format: Allocating 100 bytes starting at 0000021c`3d250000
                var match = line.toString().match(/starting at ([0-9a-fA-F`]+)/);
                if (match) {
                    return match[1].replace(/`/g, "");
                }
            }
        } catch (e) {
            Logger.error("Memory allocation failed: " + e.message);
        }
        return null;
    }
}

class CommandLineUtils {
    static get() {
        try {
            var peb = host.currentProcess.Environment.EnvironmentBlock;
            var cmdLine = peb.ProcessParameters.CommandLine.Buffer;
            return host.memory.readWideString(cmdLine);
        } catch (e) { return ""; }
    }

    static parseSwitches(cmdLine) {
        var switches = [];
        var regex = /--([\w-]+)(=("[^"]*"|[^\s]*))?/g;
        var match;
        while ((match = regex.exec(cmdLine)) !== null) {
            switches.push({ name: match[1], value: (match[3] || "").replace(/"/g, '') });
        }
        return switches;
    }

    static escapeRegExp(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    static getSwitch(cmdLine, name) {
        var escapedName = this.escapeRegExp(name);
        var match = cmdLine.match(new RegExp("--" + escapedName + "(=([^\\s\"]+|\"[^\"]*\"))?"));
        return match ? (match[2] || "true").replace(/"/g, "") : null;
    }

    static getHostFromUrl(url) {
        if (!url) return "";
        // Match any scheme (http, https, chrome, file, etc.)
        var match = url.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^\/]+)/);
        return match ? match[1] : url;
    }
}

class BreakpointManager {
    static set(title, targets, description) {
        Logger.section(title);
        var ctl = SymbolUtils.getControl();

        for (var t of targets) {
            var sym = (typeof t === 'string') ? t : t.sym;
            var desc = (typeof t === 'string') ? "" : (" (" + t.desc + ")");
            var cmd = (typeof t === 'string') ? ("bp " + t) : (t.cmd ? t.cmd : "bp " + t.sym);

            Logger.info(cmd + desc);
            try { ctl.ExecuteCommand(cmd); } catch (e) { Logger.debug("Breakpoint set failed for " + sym + ": " + e.message); }
        }

        if (description) Logger.info("Useful for: " + description + "\n");
    }
}

/// Integrity level SID lookup table
const INTEGRITY_LEVELS = {
    "S-1-16-0": "Untrusted",
    "S-1-16-4096": "Low",
    "S-1-16-8192": "Medium",
    "S-1-16-12288": "High",
    "S-1-16-16384": "System",
    "S-1-15-2": "AppContainer"
};

/// Centralized breakpoint configurations (DRY)
const BREAKPOINT_CONFIGS = {
    element: {
        title: "DOM Element Creation Breakpoints",
        targets: [
            "chrome!blink::Document::CreateRawElement",
            "chrome!blink::Document::createElement",
            "chrome!blink::HTMLElement::insertAdjacentHTML"
        ],
        desc: "DOM clobbering, XSS sink analysis"
    },
    nav: {
        title: "Navigation Breakpoints",
        targets: [

            "chrome!blink::Location::SetLocation",
            "chrome!blink::Location::assign",
            "chrome!blink::Location::replace",
            "chrome!blink::FrameLoader::StartNavigation"
        ],
        desc: "Navigation hijacking, URL spoofing"
    },
    pm: {
        title: "postMessage Breakpoints",
        targets: [
            "chrome!blink::LocalDOMWindow::DispatchPostMessage",
            "chrome!blink::MessageEvent::Create"
        ],
        desc: "Cross-origin message interception"
    },
    fetch: {
        title: "Fetch/XHR Breakpoints",
        targets: [
            "chrome!blink::FetchManager::Fetch",
            "chrome!blink::XMLHttpRequest::send",
            "chrome!blink::XMLHttpRequest::open"
        ],
        desc: "Request interception, CORS bypass"
    },
    compile: {
        title: "V8 Script Compilation Breakpoints",
        targets: [
            "chrome!v8::Script::Compile",
            "chrome!v8::ScriptCompiler::Compile",
            "chrome!v8::internal::Compiler::Compile"
        ],
        desc: "Analyzing JIT compilation, CSP bypass"
    },
    gc: {
        title: "V8 Garbage Collection Breakpoints",
        targets: [
            "chrome!v8::internal::Heap::CollectGarbage",
            "chrome!v8::internal::Heap::PerformGarbageCollection",
            "chrome!v8::internal::MarkCompactCollector::CollectGarbage"
        ],
        desc: "UAF exploitation, heap grooming"
    },
    wasm: {
        title: "WebAssembly Breakpoints",
        targets: [
            "chrome!v8::internal::wasm::CompileLazy",
            "chrome!v8::internal::wasm::WasmEngine::SyncCompile",
            "chrome!v8::internal::wasm::WasmCodeManager::Commit"
        ],
        desc: "WASM JIT bugs, RWX page analysis"
    },
    jit: {
        title: "V8 JIT Code Generation Breakpoints",
        targets: [
            "chrome!v8::internal::OptimizedCompilationJob::ExecuteJob",
            "chrome!v8::internal::Builtins::Generate_*",
            "chrome!v8::internal::MacroAssembler::Call"
        ],
        desc: "JIT spray, code injection analysis"
    }
};

/// Helper: Create breakpoint handler from config key
function _bpFromConfig(key) {
    var cfg = BREAKPOINT_CONFIGS[key];
    return set_breakpoints(cfg.title, cfg.targets, cfg.desc);
}

/// Helper: Extract URL from dx output line
function extractUrlFromLine(lineStr) {
    var urlMatch = lineStr.match(/"(https?:\/\/[^"]+)"/) ||
        lineStr.match(/"(chrome-extension:\/\/[^"]+)"/) ||
        lineStr.match(/"(chrome:\/\/[^"]+)"/);
    return urlMatch ? urlMatch[1] : null;
}

/// Helper: Normalize an address to hex format with 0x prefix
/// Handles: decimal numbers, hex strings with/without 0x prefix, BigInt
function normalizeAddress(addr) {
    if (addr === null || addr === undefined) return null;
    var addrStr = addr.toString();
    if (addrStr.startsWith("0x") || addrStr.startsWith("0X")) {
        return addrStr;
    } else if (/^\d+$/.test(addrStr)) {
        // Decimal number - convert to hex
        return "0x" + BigInt(addrStr).toString(16);
    } else {
        // Assume hex without prefix
        return "0x" + addrStr;
    }
}

/// Helper: Check if a pointer value is valid (not null/zero)
/// Handles various representations: null, "0", "00000000", 0, BigInt(0), etc.
function isValidPointer(ptr) {
    if (ptr === null || ptr === undefined) return false;
    if (ptr === 0 || ptr === 0n) return false;
    var str = ptr.toString().replace(/`/g, "");
    if (str === "0" || str === "00000000" || str === "0000000000000000") return false;
    if (str === "0x0" || str === "0x00000000" || str === "0x0000000000000000") return false;
    return true;
}

/// Helper: Extract pointee type from smart pointer types
/// Examples:
///   "scoped_refptr<blink::SecurityOrigin>" -> "(blink::SecurityOrigin*)"
///   "scoped_refptr<const blink::SecurityOrigin>" -> "(const blink::SecurityOrigin*)"
///   "Member<blink::Document>" -> "(blink::Document*)"
///   "cppgc::internal::BasicMember<blink::ElementData,..." -> "(blink::ElementData*)"
///   "blink::SecurityOrigin *" -> "(blink::SecurityOrigin*)"
/// @param typeStr - Type string from dx output
/// @returns Type cast string like "(blink::SecurityOrigin*)" or null
function extractPointeeType(typeStr) {
    if (!typeStr) return null;

    // Pattern 1: scoped_refptr<T>, unique_ptr<T>, Member<T>, DataRef<T>, RefPtr<T>, etc.
    var match = typeStr.match(/(?:scoped_refptr|unique_ptr|Member|WeakMember|Persistent|CrossThreadPersistent|DataRef|RefPtr|base::RefCountedData)\s*<\s*([^<>,]+)/);
    if (match) {
        return "(" + match[1].trim() + "*)";
    }

    // Pattern 2: cppgc::internal::BasicMember<T, ...>
    match = typeStr.match(/BasicMember\s*<\s*([^,<>]+)/);
    if (match) {
        return "(" + match[1].trim() + "*)";
    }

    // Pattern 3: Already a pointer type "T *" or "T*"
    match = typeStr.match(/^([a-zA-Z_][a-zA-Z0-9_:]*(?:\s+const)?)\s*\*\s*$/);
    if (match) {
        return "(" + match[1].trim() + "*)";
    }

    // Pattern 4: Any template with single type arg - extract inner type as best guess
    // e.g., "SomeWrapper<blink::StyleFoo>" -> "(blink::StyleFoo*)"
    match = typeStr.match(/^[a-zA-Z_][a-zA-Z0-9_:]*\s*<\s*([a-zA-Z_][a-zA-Z0-9_:]+)\s*>$/);
    if (match) {
        return "(" + match[1].trim() + "*)";
    }

    return null;
}

/// Helper: Get a compressed member pointer value using symbols
/// @param baseAddr - Base address (with or without 0x prefix)
/// @param typeCast - Type cast string, e.g. "(blink::WebLocalFrameImpl*)"
/// @param memberName - Member name to read
/// @returns Compressed pointer value or null
function getCompressedMember(baseAddr, typeCast, memberName) {
    try {
        var ctl = SymbolUtils.getControl();
        var cmd = "dx &(" + typeCast + baseAddr + ")->" + memberName;
        var out = ctl.ExecuteCommand(cmd);
        for (var line of out) {
            var l = line.toString();
            var m = l.match(/:\s*(0x[0-9a-fA-F`]+)/);
            if (m) {
                var addr = m[1].replace(/`/g, "");
                try {
                    var ptrVal = host.memory.readMemoryValues(host.parseInt64(addr, 16), 1, 4)[0];
                    return ptrVal;
                } catch (e) { Logger.error("ReadMem failed: " + e.message); }
            }
        }
    } catch (e) { Logger.debug("getCompressedMember failed: " + e.message); }
    return null;
}

/// Helper: Read URL string from dx output for a url_.string_ member
/// @param addr - Address of the object containing url_
/// @param typeCast - Type cast string, e.g. "(blink::DocumentLoader*)"
/// @returns URL string or null
function readUrlStringFromDx(addr, typeCast) {
    try {
        var ctl = SymbolUtils.getControl();
        var dxCmd = "dx -r2 (" + typeCast + "0x" + addr + ")->url_.string_";
        var output = ctl.ExecuteCommand(dxCmd);
        for (var line of output) {
            var sLine = line.toString();
            if (sLine.indexOf("AsciiText") !== -1 || sLine.indexOf("Text") !== -1) {
                var m = sLine.match(/\"(.*)\"/);
                if (m) return m[1];
            }
        }
    } catch (e) { Logger.debug("readUrlStringFromDx failed: " + e.message); }
    return null;
}

/// Helper: Patch strings in memory (used by spoof_origin)
/// @param ctl - Debugger control object
/// @param searchStr - String to search for
/// @param replaceStr - Replacement string
/// @param label - Label for logging
/// @param isUnicode - Whether to search for Unicode strings
/// @returns Number of patched occurrences
function _patchStringInMemory(ctl, searchStr, replaceStr, label, isUnicode) {
    if (replaceStr.length > searchStr.length) {
        Logger.warn("  " + label + ": Replacement string too long (" + replaceStr.length + " > " + searchStr.length + "). Aborting to prevent overflow.");
        return 0;
    }

    try {
        var cmdType = isUnicode ? "-u" : "-a";
        var searchCmd = 's ' + cmdType + ' 0 L?' + USER_MODE_ADDR_LIMIT + ' "' + searchStr + '"';
        var output = ctl.ExecuteCommand(searchCmd);

        var addresses = [];
        for (var line of output) {
            var addr = SymbolUtils.extractAddress(line);
            if (addr) addresses.push(addr);
        }

        if (addresses.length === 0) {
            return 0;
        }

        var patched = 0;
        for (var addr of addresses) {
            try {
                // StringImpl Layout (approx): RefCount(+0), Length(+4), Hash(+8), Data(+12)
                // So Length is at Data - 8.
                // Try multiple offsets to find the length field for variable-length string support
                var addrVal = host.parseInt64(addr, 16);
                var lengthUpdated = false;

                // Try multiple offsets for StringImpl length field:
                // -8: Standard layout (Data at +12, Length at +4, so Data - Length = -8)
                // -4: Alternate layout with different padding
                // -12: Older StringImpl layouts
                var lenOffsets = [-8, -4, -12];
                for (var offsetIdx = 0; offsetIdx < lenOffsets.length && !lengthUpdated; offsetIdx++) {
                    try {
                        var lenAddr = addrVal.add(lenOffsets[offsetIdx]);
                        var ptrVal = host.memory.readMemoryValues(lenAddr, 1, 4)[0];

                        // Memory safety: Only update length if we're confident this is the length field
                        // - Must EXACTLY match searchStr.length (not just >= to prevent false positives)
                        // - Must be reasonable (<MAX_URL_STRING_LENGTH chars for a URL)
                        if (ptrVal === searchStr.length && ptrVal < MAX_URL_STRING_LENGTH) {
                            // Update length to replaceStr.length
                            var newLen = replaceStr.length;
                            MemoryUtils.writeU32(lenAddr, newLen);
                            lengthUpdated = true;
                        }
                    } catch (e) {
                        // Ignore read errors, try next offset
                    }
                }

                // Write the replacement string data
                var bytes = [];
                for (var i = 0; i < replaceStr.length; i++) {
                    var code = replaceStr.charCodeAt(i);
                    if (isUnicode) {
                        bytes.push(code & 0xFF);
                        bytes.push((code >> 8) & 0xFF);
                    } else {
                        bytes.push(code & 0xFF);
                    }
                }

                // Pad remainder with nulls to overwrite old longer string
                for (var k = replaceStr.length; k < searchStr.length; k++) {
                    if (isUnicode) { bytes.push(0); bytes.push(0); }
                    else bytes.push(0);
                }

                MemoryUtils.writeMemory(addr, bytes);
                patched++;
            } catch (e) { Logger.debug("Memory write failed at " + addr + ": " + e.message); }
        }

        Logger.info("  " + label + ": Patched " + patched + "/" + addresses.length + " " + (isUnicode ? "Unicode" : "ASCII") + " occurrences");
        return patched;
    } catch (e) {
        Logger.debug("_patchStringInMemory failed: " + e.message);
        return 0;
    }
}

/// =============================================================================
/// BLINK DOM UNWRAPPING UTILITIES
/// =============================================================================

/// BlinkUnwrap: Utility class for traversing Blink DOM objects using pointer decompression
class BlinkUnwrap {
    /// Get LocalFrame from WebLocalFrameImpl
    /// Path: WebLocalFrameImpl -> frame_ (compressed) -> LocalFrame
    static getLocalFrame(webFrameAddr) {
        var webFrameHex = normalizeAddress(webFrameAddr);
        if (!webFrameHex) return null;
        var frameCompressed = getCompressedMember(webFrameHex, "(blink::WebLocalFrameImpl*)", "frame_");
        if (frameCompressed === null) return null;
        return MemoryUtils.decompressCppgcPtr(frameCompressed, webFrameAddr);
    }

    /// Get LocalDOMWindow from LocalFrame
    /// Path: LocalFrame -> dom_window_ (compressed) -> LocalDOMWindow
    static getDomWindow(localFrameAddr) {
        var frameHex = normalizeAddress(localFrameAddr);
        if (!frameHex) return null;
        var windowCompressed = getCompressedMember(frameHex, "(blink::LocalFrame*)", "dom_window_");
        if (windowCompressed === null) return null;
        return MemoryUtils.decompressCppgcPtr(windowCompressed, localFrameAddr);
    }

    /// Get Document from LocalDOMWindow
    /// Path: LocalDOMWindow -> document_ (compressed) -> Document
    static getDocument(domWindowAddr) {
        var windowHex = normalizeAddress(domWindowAddr);
        if (!windowHex) return null;
        var docCompressed = getCompressedMember(windowHex, "(blink::LocalDOMWindow*)", "document_");
        if (docCompressed === null) return null;
        return MemoryUtils.decompressCppgcPtr(docCompressed, domWindowAddr);
    }

    /// Get Document directly from LocalFrame (convenience method)
    static getDocumentFromFrame(localFrameAddr) {
        var domWindow = this.getDomWindow(localFrameAddr);
        if (!domWindow || domWindow === "0") return null;
        return this.getDocument(domWindow);
    }

    /// Get SecurityOrigin URL from Document
    static getSecurityOriginUrl(documentAddr) {
        try {
            var ctl = SymbolUtils.getControl();
            var docHex = normalizeAddress(documentAddr);
            if (!docHex) return null;
            var cmd = "dx -r3 ((blink::Document*)" + docHex + ")->GetExecutionContext()->GetSecurityOrigin()->ToUrlOrigin().GetDebugString()";
            var output = ctl.ExecuteCommand(cmd);
            for (var line of output) {
                var lineStr = line.toString();
                var urlMatch = lineStr.match(/"([^"]+)"/);
                if (urlMatch) return urlMatch[1];
            }
            return readUrlStringFromDx(documentAddr.replace(/^0x/, ""), "(blink::Document*)");
        } catch (e) { }
        return null;
    }

    /// Get a C++ member value from an object
    /// @param objectAddr - Address of the object
    /// @param typeCast - Type cast string, e.g. "(blink::Element*)"
    /// @param memberPath - Member name or path (e.g., "node_flags_" or "element_data_.ptr_")
    /// @returns Object with {value, type, raw} or null if failed
    static getCppMember(objectAddr, typeCast, memberPath) {
        var objHex = normalizeAddress(objectAddr);
        if (!objHex) return null;

        var ctl = SymbolUtils.getControl();
        try {
            var cmd = "dx -r0 (" + typeCast + objHex + ")->" + memberPath;
            var output = ctl.ExecuteCommand(cmd);
            for (var line of output) {
                var lineStr = line.toString();

                // Check for error messages
                if (lineStr.indexOf("Unable to bind") !== -1) return null;
                if (lineStr.indexOf("Error:") !== -1) return null;
                if (lineStr.indexOf("Couldn't resolve") !== -1) return null;
                if (lineStr.indexOf("No type information") !== -1) return null;

                // Extract type first
                var typeMatch = lineStr.match(/\[Type:\s*([^\]]+)\]/);
                var typeStr = typeMatch ? typeMatch[1] : "unknown";

                // Check if this is a BasicMember/Member pointer type that needs decompression
                if (typeStr.indexOf("BasicMember") !== -1 || typeStr.indexOf("Member<") !== -1 ||
                    typeStr.indexOf("scoped_refptr") !== -1 || typeStr.indexOf("WeakMember") !== -1) {
                    // For pointer types, get the raw compressed value and decompress it
                    try {
                        var rawCmd = "dx &((" + typeCast + objHex + ")->" + memberPath + ".raw_)";
                        var rawOutput = ctl.ExecuteCommand(rawCmd);
                        var rawAddr = null;
                        for (var rawLine of rawOutput) {
                            var rawMatch = rawLine.toString().match(/:\s+(0x[0-9a-fA-F`]+)/);
                            if (rawMatch) {
                                rawAddr = rawMatch[1].replace(/`/g, "");
                                break;
                            }
                        }
                        if (rawAddr) {
                            var compressedVal = host.memory.readMemoryValues(host.parseInt64(rawAddr, 16), 1, 4)[0];
                            if (compressedVal === 0) {
                                return { value: "null", type: typeStr, raw: lineStr };
                            }
                            var decompressed = MemoryUtils.decompressCppgcPtr(compressedVal, objHex);
                            if (decompressed && decompressed !== "0") {
                                var pointeeType = extractPointeeType(typeStr);
                                return { value: "0x" + decompressed + (pointeeType ? " " + pointeeType : ""), type: typeStr, raw: lineStr };
                            }
                        }
                    } catch (ptrErr) { }
                    // Fallback: return the type description
                    return { value: "(pointer type - use frame_attrs)", type: typeStr, raw: lineStr };
                }

                // Parse value from "member : value [Type: ...]" format
                // Fix: Require space after colon to avoid matching "blink::Type"
                var match = lineStr.match(/:\s+(.+?)\s*(?:\[Type:|$)/);
                if (match) {
                    var rawValue = match[1].trim();
                    // Skip if value looks like an error
                    if (rawValue.indexOf("Unable to") !== -1) return null;
                    return { value: rawValue, type: typeStr, raw: lineStr };
                }
            }
        } catch (e) { }
        return null;
    }

    /// Set a C++ member value on an object (integers/pointers only)
    /// @param objectAddr - Address of the object
    /// @param typeCast - Type cast string, e.g. "(blink::Element*)"
    /// @param memberPath - Member name
    /// @param value - Value to write (number or hex string)
    /// @returns true if successful
    static setCppMember(objectAddr, typeCast, memberPath, value) {
        var objHex = normalizeAddress(objectAddr);
        if (!objHex) return false;

        var ctl = SymbolUtils.getControl();
        try {
            // First, get member info (address and type)
            var memberCmd = "dx &(" + typeCast + objHex + ")->" + memberPath;
            var memberOutput = ctl.ExecuteCommand(memberCmd);
            var memberAddr = null;
            for (var line of memberOutput) {
                var m = line.toString().match(/:\s+(0x[0-9a-fA-F`]+)/);
                if (m) {
                    memberAddr = m[1].replace(/`/g, "");
                    break;
                }
            }
            if (!memberAddr) {
                Logger.error("Could not get member address");
                return false;
            }

            // Get member type from dx
            var typeCmd = "dx (" + typeCast + objHex + ")->" + memberPath;
            var typeOutput = ctl.ExecuteCommand(typeCmd);
            var memberType = "";
            for (var line of typeOutput) {
                var typeMatch = line.toString().match(/\[Type:\s*([^\]]+)\]/);
                if (typeMatch) {
                    memberType = typeMatch[1].trim();
                    break;
                }
            }

            // Handle different types
            if (memberType.indexOf("blink::String") !== -1 || memberType.indexOf("WTF::String") !== -1) {
                // String type - find StringImpl and write characters
                var implCmd = "dx &((" + typeCast + objHex + ")->" + memberPath + ".impl_.ptr_)";
                var implOutput = ctl.ExecuteCommand(implCmd);
                var implPtrAddr = null;
                for (var line of implOutput) {
                    var m = line.toString().match(/:\s+(0x[0-9a-fA-F`]+)/);
                    if (m) {
                        implPtrAddr = m[1].replace(/`/g, "");
                        break;
                    }
                }

                if (implPtrAddr) {
                    // Read the StringImpl* from the impl_.ptr_ field
                    var implPtr = host.memory.readMemoryValues(host.parseInt64(implPtrAddr, 16), 1, 8)[0];
                    var implAddrBig = MemoryUtils.parseBigInt(implPtr);
                    if (implAddrBig !== 0n) {
                        var implAddr = "0x" + implAddrBig.toString(16);
                        MemoryUtils.writeStringImpl(implAddr, value);
                        Logger.info("[C++] String written via StringImpl at " + implAddr);
                        return true;
                    }
                }
                Logger.error("Could not find StringImpl for String member");
                return false;
            }
            else if (memberType === "bool") {
                // Boolean - write 1 byte
                var boolVal = (value === "true" || value === "1" || value === true) ? 1 : 0;
                var writeCmd = "eb " + memberAddr + " " + boolVal;
                ctl.ExecuteCommand(writeCmd);
                return true;
            }
            else if (memberType.indexOf("unsigned int") !== -1 || memberType.indexOf("uint32_t") !== -1 ||
                memberType.indexOf("int") !== -1 || memberType.indexOf("uint16_t") !== -1 ||
                memberType.indexOf("short") !== -1) {
                // 32-bit or smaller integer
                MemoryUtils.writeU32(memberAddr, parseIntAuto(value));
                return true;
            }
            else if (memberType.indexOf("uint64_t") !== -1 || memberType.indexOf("size_t") !== -1 ||
                memberType.indexOf("uintptr_t") !== -1 || memberType.indexOf("*") !== -1) {
                // 64-bit value or pointer
                var numericValue = BigInt(parseIntAuto(value));
                var writeCmd = "eq " + memberAddr + " " + numericValue.toString(16);
                ctl.ExecuteCommand(writeCmd);
                return true;
            }
            else {
                // Default: try 32-bit write
                Logger.info("[C++] Unknown type '" + memberType + "', trying 32-bit write...");
                var numericValue = parseIntAuto(value);
                if (isNaN(numericValue)) {
                    Logger.error("Cannot convert value '" + value + "' to numeric");
                    return false;
                }
                MemoryUtils.writeU32(memberAddr, numericValue);
                return true;
            }
        } catch (e) {
            Logger.error("setCppMember failed: " + e.message);
        }
        return false;
    }

    /// Enumerate C++ members of an object
    /// @param objectAddr - Address of the object
    /// @param typeCast - Type cast string, e.g. "(blink::Element*)"
    /// @returns Array of {name, value, type} objects
    static getCppMembers(objectAddr, typeCast) {
        var objHex = normalizeAddress(objectAddr);
        if (!objHex) return [];

        var ctl = SymbolUtils.getControl();
        var members = [];
        try {
            var cmd = "dx -r1 (" + typeCast + objHex + ")";
            var output = ctl.ExecuteCommand(cmd);
            for (var line of output) {
                var lineStr = line.toString();

                // Skip empty lines and header
                if (lineStr.trim().length === 0) continue;
                if (lineStr.indexOf("(" + typeCast) !== -1) continue; // Header line

                // Parse format: "    [+0x048] tag_name_        : value [Type: ...]"
                // or: "    [+0x058] element_data_    [Type: ...]" (no colon before type)
                var offsetMatch = lineStr.match(/\[\+0x[0-9a-fA-F]+\]\s+(.+)$/);
                if (!offsetMatch) continue;

                var afterOffset = offsetMatch[1];

                // Skip base class entries like "blink::ContainerNode [Type: ...]"
                if (afterOffset.match(/^[a-zA-Z_][a-zA-Z0-9_]*::[a-zA-Z_]/)) continue;

                // Try to parse "member_ : value [Type: ...]" format
                var colonMatch = afterOffset.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.+)$/);
                if (colonMatch) {
                    var name = colonMatch[1];
                    var rest = colonMatch[2].trim();
                    var typeMatch = rest.match(/\[Type:\s*([^\]]+)\]\s*$/);
                    var type = typeMatch ? typeMatch[1] : "unknown";
                    var value = typeMatch ? rest.replace(/\s*\[Type:[^\]]+\]\s*$/, "").trim() : rest;
                    if (value.length === 0) value = "{...}";
                    members.push({ name: name, value: value, type: type });
                    continue;
                }

                // Try to parse "member_ [Type: ...]" format (no colon)
                var noColonMatch = afterOffset.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s+\[Type:\s*([^\]]+)\]/);
                if (noColonMatch) {
                    members.push({ name: noColonMatch[1], value: "{...}", type: noColonMatch[2] });
                }
            }
        } catch (e) { Logger.debug("getCppMembers parse error: " + e.message); }
        return members;
    }





    /// Detect the type of a Blink object using its vtable
    /// Supports backward scanning to detect embedded struct types.
    static detectType(objectAddr, debug, noScan) {
        var objHex = normalizeAddress(objectAddr);
        if (!objHex) return null;

        try {
            // 1. Direct VTable Check
            var vtablePtr = host.memory.readMemoryValues(host.parseInt64(objHex, 16), 1, 8)[0];
            if (debug) Logger.info("  [Debug] VTable Ptr at " + objHex + ": 0x" + vtablePtr.toString(16));

            if (vtablePtr.compareTo(0) !== 0) {
                var symName = SymbolUtils.getSymbolName(vtablePtr.toString(16), debug);
                if (symName) {
                    // Pattern 1: Standard vtable symbol (chrome!blink::ClassName::`vftable' or ::vftable)
                    // Handle both ::vftable and ::`vftable' formats
                    var matchVftable = symName.match(/!([a-zA-Z0-9_:]+)::(?:`vftable'|vftable)/);
                    if (matchVftable) {
                        var className = matchVftable[1];
                        if (debug) Logger.info("  [Debug] Detected Type (Std): " + className);
                        return "(" + className + "*)";
                    }

                    // Pattern 2: MSVC mangled vtable symbol (??_7...)
                    var matchMangled = symName.match(/\?\?_7([a-zA-Z0-9_]+)/);
                    if (matchMangled) {
                        var rawName = matchMangled[1];
                        // Strip "blink" suffix from mangled names (5 = "blink".length)
                        if (rawName.endsWith("blink") && rawName.length > "blink".length) {
                            rawName = rawName.substring(0, rawName.length - "blink".length);
                        }
                        var fullType = (rawName.indexOf("::") === -1) ? "blink::" + rawName : rawName;
                        if (debug) Logger.info("  [Debug] Detected Type (Mangled): " + fullType);
                        return "(" + fullType + "*)";
                    }

                    // Pattern 3: Fallback - any symbol with module!namespace::ClassName:: pattern
                    var matchFallback = symName.match(/!([a-zA-Z_][a-zA-Z0-9_:]*)::/);
                    if (matchFallback) {
                        var className = matchFallback[1];
                        if (debug) Logger.info("  [Debug] Detected Type (Fallback): " + className);
                        return "(" + className + "*)";
                    }
                }
            }
        } catch (e) {
            if (debug) Logger.info("  [Debug] detectType direct check failed: " + e.message);
        }

        // NOTE: Backward scan disabled - it was slow and produced false matches.
        // Types without vtables (like SecurityOrigin) cannot be auto-detected.
        // The pointer-following logic will still work; users can cast manually with dx.

        return null;
    }

    /// Get C++ member using detected type
    /// @param objectAddr - Address of the object
    /// @param memberPath - Member name
    /// @param typeHint - Optional type hint for non-vtable types
    /// @returns Object with {value, type, raw, typeCast} or null
    static getCppMemberWithFallback(objectAddr, memberPath, typeHint) {
        // Try detected type first
        var detectedType = this.detectType(objectAddr);
        if (detectedType) {
            var result = this.getCppMember(objectAddr, detectedType, memberPath);
            if (result) {
                result.typeCast = detectedType;
                return result;
            }
        }

        // If typeHint provided, try that
        if (typeHint) {
            var result = this.getCppMember(objectAddr, typeHint, memberPath);
            if (result) {
                result.typeCast = typeHint;
                return result;
            }
        }

        return null;
    }

    /// Get the pointer address of a member (with decompression if needed)
    /// @param objectAddr - Address of the object
    /// @param typeCast - Type cast string
    /// @param memberPath - Member name
    /// @returns Decompressed pointer address string or null
    static getMemberPointer(objectAddr, typeCast, memberPath) {
        var objHex = normalizeAddress(objectAddr);
        if (!objHex) return null;

        var ctl = SymbolUtils.getControl();
        try {
            // Try to get the address of the member
            var cmd = "dx &(" + typeCast + objHex + ")->" + memberPath;
            var output = ctl.ExecuteCommand(cmd);
            for (var line of output) {
                var lineStr = line.toString();
                // Look for address like "0x12345678" or "0x12345678`abcdefab"
                // Fix: Ensure we match the value after the colon (space required)
                var match = lineStr.match(/:\s+(0x[0-9a-fA-F`]+)/);
                if (match) {
                    var addr = match[1].replace(/`/g, "");

                    // Check if this is a compressed pointer (high bits are 0)
                    if (addr.length <= 10) { // Compressed (32-bit)
                        // Try to decompress
                        var decompressed = MemoryUtils.decompressCppgcPtr(addr, objHex);
                        if (decompressed) return "0x" + decompressed;
                    }
                    return addr;
                }
            }
        } catch (e) { }
        return null;
    }

    /// Set C++ member using detected type
    /// @param objectAddr - Address of the object
    /// @param memberPath - Member name
    /// @param value - Value to write
    /// @param typeHint - Optional type hint for non-vtable types
    /// @returns true if successful
    static setCppMemberWithFallback(objectAddr, memberPath, value, typeHint) {
        // Try detected type first
        var detectedType = this.detectType(objectAddr);
        if (detectedType) {
            if (this.setCppMember(objectAddr, detectedType, memberPath, value)) {
                return true;
            }
        }

        // If typeHint provided, try that
        if (typeHint) {
            if (this.setCppMember(objectAddr, typeHint, memberPath, value)) {
                return true;
            }
        }

        return false;
    }

    /// Get C++ members with fallback across multiple Blink types
    /// @param objectAddr - Address of the object
    /// @param debug - Enable debug logging
    /// @param typeHint - Optional type hint (e.g., "(blink::SecurityOrigin*)") to try if vtable detection fails
    /// @returns Object with {members: Array, typeCast: string} or {members: [], typeCast: null}
    static getCppMembersWithFallback(objectAddr, debug, typeHint) {
        // 1. Try detected type first (vtable-based)
        var detectedType = this.detectType(objectAddr, debug);
        if (detectedType) {
            var members = this.getCppMembers(objectAddr, detectedType);
            if (members.length > 0) {
                return { members: members, typeCast: detectedType };
            }
        }

        // 2. If typeHint provided, try that
        if (typeHint) {
            var members = this.getCppMembers(objectAddr, typeHint);
            if (members.length > 0) {
                return { members: members, typeCast: typeHint };
            }
        }

        // 3. No type detected or hinted - return empty
        return { members: [], typeCast: null };
    }

    /// Get Document URL
    static getDocumentUrl(documentAddr) {
        var docHex = documentAddr.toString().replace(/^0x/, "");
        return readUrlStringFromDx(docHex, "(blink::Document*)");
    }

    /// Get first child of a node (ContainerNode::first_child_)
    static getFirstChild(nodeAddr) {
        var nodeHex = normalizeAddress(nodeAddr);
        if (!nodeHex) return null;
        var childCompressed = getCompressedMember(nodeHex, "(blink::ContainerNode*)", "first_child_");
        if (childCompressed === null) return null;
        var res = MemoryUtils.decompressCppgcPtr(childCompressed, nodeAddr);
        return res;
    }

    /// Get next sibling of a node (Node::next_)
    static getNextSibling(nodeAddr) {
        var nodeHex = normalizeAddress(nodeAddr);
        if (!nodeHex) return null;
        var siblingCompressed = getCompressedMember(nodeHex, "(blink::Node*)", "next_");
        if (siblingCompressed === null) return null;
        return MemoryUtils.decompressCppgcPtr(siblingCompressed, nodeAddr);
    }

    /// Helper: Parse string from dx output
    static _parseStringFromDxOutput(output) {
        for (var line of output) {
            var s = line.toString();
            // Check for [AsciiText] : "value" or [Text] : "value"
            var match = s.match(/\[(Ascii)?Text\]\s*:\s*"([^"]*)"/);
            if (match) return match[2];

            // Check for "value" (simple quote) - but not empty
            var match2 = s.match(/^"([^"]+)"$/);
            if (match2) return match2[1];

            // Check for Prop : "value" pattern
            var match3 = s.match(/:\s*"([^"]+)"/);
            if (match3) return match3[1];

            // Check for string_ : ... "value" pattern
            var match4 = s.match(/string_.*"([^"]+)"/);
            if (match4) return match4[1];

            // Check for impl_ with quoted string
            var match5 = s.match(/impl_.*"([^"]+)"/);
            if (match5) return match5[1];

            // Fallback: look for any quoted string with Text label
            if (s.indexOf("Text") !== -1) {
                var m = s.match(/"([^"]+)"/);
                if (m) return m[1];
            }

            // Look for URL patterns (often appear in attribute values)
            var urlMatch = s.match(/(https?:\/\/[^\s"]+)/);
            if (urlMatch) return urlMatch[1];
        }
        return null;
    }

    /// Helper: Extract attribute value using multiple fallback paths
    /// @param base - Base dx expression for the attribute (e.g., "((blink::UniqueElementData*)0x...)->attribute_vector_[0]")
    /// @returns The attribute value string or null
    static _extractAttributeValue(base) {
        var ctl = SymbolUtils.getControl();
        var valStr = null;

        // Path 1: Direct value_ access
        try {
            var vOut = ctl.ExecuteCommand("dx -r3 " + base + ".value_");
            valStr = BlinkUnwrap._parseStringFromDxOutput(vOut);
            if (valStr) return valStr;
        } catch (e) { }

        // Path 2: Try value_.string_ for AtomicString
        try {
            var vOut2 = ctl.ExecuteCommand("dx -r3 " + base + ".value_.string_");
            valStr = BlinkUnwrap._parseStringFromDxOutput(vOut2);
            if (valStr) return valStr;
        } catch (e) { }

        // Path 3: Direct AtomicString impl access
        try {
            var vOut3 = ctl.ExecuteCommand("dx -r2 " + base + ".value_.impl_");
            valStr = BlinkUnwrap._parseStringFromDxOutput(vOut3);
            if (valStr) return valStr;
        } catch (e) { }

        // Path 4: Fallback to looking for any quoted string in dx output
        try {
            var vOut4 = ctl.ExecuteCommand("dx -r4 " + base);
            for (var line of vOut4) {
                var lineStr = line.toString();
                if (lineStr.indexOf("value_") !== -1 || lineStr.indexOf("Value") !== -1) {
                    var m = lineStr.match(/"([^"]+)"/);
                    if (m) return m[1];
                }
            }
            // Last resort: any quoted string
            for (var line of vOut4) {
                var m = line.toString().match(/"([^"]+)"/);
                if (m) return m[1];
            }
        } catch (e) { }

        return null;
    }

    /// Get node name (tag name)
    static getNodeName(nodeAddr) {
        var ctl = SymbolUtils.getControl();
        var nodeHex = normalizeAddress(nodeAddr);
        if (!nodeHex) return null;

        try {
            // Read node_flags_ to check type (avoid virtual calls)
            var cmd = "dx -r0 ((blink::Node*)" + nodeHex + ")->node_flags_";
            var output = ctl.ExecuteCommand(cmd);
            var flags = null;
            for (var line of output) {
                var s = line.toString();
                // Match decimal or hex from "node_flags_ : value"
                var m = s.match(/:[ ]*(0x[0-9a-fA-F]+|\d+)/);
                if (m) {
                    flags = parseIntAuto(m[1]);
                    break;
                }
            }

            if (flags !== null) {
                var type = flags & 0xF;
                // kElementNode = 1
                if (type === 1) {
                    var cmdE = "dx -r2 ((blink::Element*)" + nodeHex + ")->tag_name_.impl_->local_name_.string_";
                    var res = BlinkUnwrap._parseStringFromDxOutput(ctl.ExecuteCommand(cmdE));
                    if (res) return res;
                    return "ELEMENT (Name unreadable)";
                }
                if (type === 3) return "#text";
                if (type === 8) return "#comment";
                if (type === 9) return "#document";
                if (type === 10) return "#doctype";
                if (type === 11) return "#document-fragment";
            }
        } catch (e) { }

        // Fallback: Try virtual function if flags check failed
        try {
            var cmd = "dx -r2 ((blink::Node*)" + nodeHex + ")->nodeName()";
            var res = BlinkUnwrap._parseStringFromDxOutput(ctl.ExecuteCommand(cmd));
            if (res) return res;
        } catch (e) { }

        return null;
    }
    /// Helper: Traverse attributes of an element
    /// callback(name, baseExpression) -> return true to stop
    /// @param elementAddr - Element address
    /// @param callback - Function to call for each attribute
    /// @param debug - If true, output debug info
    static _traverseAttributes(elementAddr, callback, debug) {
        var elemHex = normalizeAddress(elementAddr);
        if (!elemHex) {
            if (debug) Logger.warn("_traverseAttributes: Invalid element address");
            return;
        }

        var ctl = SymbolUtils.getControl();

        // First, try to read element_data_ as a compressed pointer
        var dataCompressed = getCompressedMember(elemHex, "(blink::Element*)", "element_data_");

        if (debug) {
            Logger.info("  [Debug] Element: " + elemHex);
            Logger.info("  [Debug] element_data_ compressed: " + (dataCompressed !== null ? "0x" + dataCompressed.toString(16) : "null"));
        }

        // If compressed pointer approach failed, try direct dx access
        if (!dataCompressed || dataCompressed === 0) {
            // Try direct dx to see if element_data_ exists
            if (debug) {
                try {
                    var dxCmd = "dx -r1 ((blink::Element*)" + elemHex + ")->element_data_";
                    var dxOut = ctl.ExecuteCommand(dxCmd);
                    for (var line of dxOut) {
                        Logger.info("  [Debug] dx element_data_: " + line.toString());
                    }
                } catch (e) {
                    Logger.info("  [Debug] dx element_data_ failed: " + e.message);
                }
            }
            return;
        }

        var dataAddr = MemoryUtils.decompressCppgcPtr(dataCompressed, elemHex);

        if (debug) {
            Logger.info("  [Debug] ElementData decompressed: 0x" + dataAddr);
        }

        if (!isValidPointer(dataAddr)) return;

        // Try to determine ElementData type via bit_field_ first
        // ElementData::bit_field_ contains is_unique flag in bit 0
        var bitField = 0;
        var isUnique = null; // null = unknown, true/false = detected

        try {
            var cmd = "dx -r0 ((blink::ElementData*)0x" + dataAddr + ")->bit_field_.bits_";
            var output = ctl.ExecuteCommand(cmd);
            for (var line of output) {
                var lineStr = line.toString();
                if (lineStr.indexOf("Unable to") !== -1 || lineStr.indexOf("Error") !== -1) continue;
                var m = lineStr.match(/:\s*(0x[0-9a-fA-F]+|\d+)/);
                if (m) {
                    bitField = parseIntAuto(m[1]);
                    // bit 0 = is_unique flag
                    isUnique = (bitField & ELEMENT_DATA_UNIQUE_FLAG) !== 0;
                    if (debug) {
                        Logger.info("  [Debug] bitField: 0x" + bitField.toString(16) + " isUnique: " + isUnique);
                    }
                    break;
                }
            }
        } catch (e) {
            if (debug) Logger.info("  [Debug] bit_field_ read failed: " + e.message);
        }

        var count = 0;

        // If bitfield detection failed, try probing both types
        if (isUnique === null) {
            if (debug) Logger.info("  [Debug] bitField detection failed, probing types...");

            // Try UniqueElementData first (more common for elements with attributes)
            try {
                var probeCmd = "dx -r0 ((blink::UniqueElementData*)0x" + dataAddr + ")->attribute_vector_[0]";
                var probeOut = ctl.ExecuteCommand(probeCmd);
                for (var line of probeOut) {
                    var lineStr = line.toString();
                    if (lineStr.indexOf("[Type:") !== -1 && lineStr.indexOf("Unable to") === -1) {
                        isUnique = true;
                        if (debug) Logger.info("  [Debug] Detected UniqueElementData via probe");
                        break;
                    }
                }
            } catch (e) { }

            if (isUnique === null) {
                // Try ShareableElementData
                try {
                    var probeCmd2 = "dx -r0 ((blink::ShareableElementData*)0x" + dataAddr + ")->attribute_array_[0]";
                    var probeOut2 = ctl.ExecuteCommand(probeCmd2);
                    for (var line of probeOut2) {
                        var lineStr = line.toString();
                        if (lineStr.indexOf("[Type:") !== -1 && lineStr.indexOf("Unable to") === -1) {
                            isUnique = false;
                            if (debug) Logger.info("  [Debug] Detected ShareableElementData via probe");
                            break;
                        }
                    }
                } catch (e) { }
            }
        }

        // If still unknown, give up
        if (isUnique === null) {
            if (debug) Logger.info("  [Debug] Could not determine ElementData type - skipping");
            return;
        }

        if (isUnique) {
            // UniqueElementData: probe to find count since size_ may be unreliable
            for (var probe = 0; probe < 100; probe++) {
                try {
                    var probeCmd = "dx -r0 ((blink::UniqueElementData*)0x" + dataAddr + ")->attribute_vector_[" + probe + "]";
                    var probeOut = ctl.ExecuteCommand(probeCmd);
                    var valid = false;
                    for (var line of probeOut) {
                        var lineStr = line.toString();
                        if (lineStr.indexOf("out of bounds") !== -1 ||
                            lineStr.indexOf("Unable to") !== -1 ||
                            lineStr.indexOf("invalid") !== -1 ||
                            lineStr.indexOf("Error:") !== -1) {
                            break;
                        }
                        if (lineStr.indexOf("[Type:") !== -1) {
                            valid = true;
                        }
                    }
                    if (!valid) break;
                    count = probe + 1;
                } catch (e) { break; }
            }
            if (debug) Logger.info("  [Debug] UniqueElementData count via probe: " + count);
        } else {
            // ShareableElementData: use arraySize from bitfield
            var arraySize = (bitField >> 1) & ELEMENT_DATA_ARRAY_SIZE_MASK;
            if (arraySize >= 0 && arraySize <= 1000) {
                count = arraySize;
            }
            if (debug) Logger.info("  [Debug] ShareableElementData count from bitfield: " + count);
        }

        if (debug) Logger.info("  [Debug] Final count: " + count);

        for (var i = 0; i < count; i++) {
            try {
                var base = isUnique
                    ? "((blink::UniqueElementData*)0x" + dataAddr + ")->attribute_vector_[" + i + "]"
                    : "((blink::ShareableElementData*)0x" + dataAddr + ")->attribute_array_[" + i + "]";

                var nameStr = "";
                var nCmd = "dx -r2 " + base + ".name_.impl_->local_name_.string_";
                var nOut = ctl.ExecuteCommand(nCmd);
                nameStr = BlinkUnwrap._parseStringFromDxOutput(nOut);

                if (!nameStr) {
                    var fallbackCmd = "dx -r1 " + base + ".name_";
                    var fallbackOut = ctl.ExecuteCommand(fallbackCmd);
                    for (var line of fallbackOut) {
                        var m = line.toString().match(/:\s*\.\s+([^\s\[]+)/);
                        if (m) { nameStr = m[1]; break; }
                    }
                }

                if (nameStr) {
                    if (callback(nameStr, base) === true) return;
                }
            } catch (e) { Logger.debug("Attribute traversal error at index " + i + ": " + e.message); }
        }
    }

    /// Get all attributes of an element as an array of objects
    static getAttributes(elementAddr) {
        var attrs = [];

        BlinkUnwrap._traverseAttributes(elementAddr, (name, base) => {
            var valStr = BlinkUnwrap._extractAttributeValue(base);
            attrs.push({ name: name, value: valStr || "" });
        });
        return attrs;
    }

    /// Get specific attribute value
    static getAttribute(elementAddr, attrName) {
        var val = null;
        BlinkUnwrap._traverseAttributes(elementAddr, (name, base) => {
            if (name === attrName) {
                val = BlinkUnwrap._extractAttributeValue(base);
                return true; // Stop iteration
            }
        });
        return val;
    }

    /// Find StringImpl address for attribute modification
    static findAttributeStringImplAddress(elementAddr, attrName) {
        var result = null;
        var ctl = SymbolUtils.getControl();

        BlinkUnwrap._traverseAttributes(elementAddr, (name, base) => {
            if (name === attrName) {
                var ptrCmd = "dx -r0 " + base + ".value_.string_.impl_.ptr_";
                var out = ctl.ExecuteCommand(ptrCmd);
                for (var line of out) {
                    var m = line.toString().match(/:\s*(0x[0-9a-fA-F]+)/);
                    if (m) {
                        result = m[1];
                        return true;
                    }
                }
            }
        });
        return result;
    }

    /// Inspect a Blink Node using robust logic
    static inspectNode(nodeAddr) {
        var addr = normalizeAddress(nodeAddr);
        if (!addr) {
            Logger.error("Invalid node address");
            return;
        }
        Logger.section("Blink Object Inspection: " + addr);

        // Use robust name resolution
        var name = BlinkUnwrap.getNodeName(addr);
        Logger.info("Resolved Node Name: " + (name ? name : "(Unable to resolve)"));

        // Standard Object Dump
        Logger.info("[*] Object Dump (blink::Node*):");
        var ctl = SymbolUtils.getControl();
        try {
            var cmd = "dx -r1 ((blink::Node*)" + addr + ")";
            for (var line of ctl.ExecuteCommand(cmd)) Logger.info("    " + line);
        } catch (e) { Logger.error("Error dumping object: " + e.message); }
    }
}

/// Helper: Get frame by index from frame map
function _getFrameByIndex(idx) {
    var ctl = SymbolUtils.getControl();
    var lazyInstanceAddr = _findFrameMapAddress(ctl);
    if (!lazyInstanceAddr) return null;
    var mapAddr = _readFrameMapPointer(lazyInstanceAddr);
    if (!mapAddr) return null;
    var frames = _parseFrameMapEntries(ctl, mapAddr);
    if (idx < 0 || idx >= frames.length) return null;
    return frames[idx];
}

/// Set a C++ member value on any Blink object (or DOM attribute on Element)
/// @param objectAddr - Address of the object
/// @param memberName - Member name
/// @param value - New value
/// @param typeHint - Optional type hint for non-vtable types
function frame_setattr(objectAddr, memberName, value, typeHint) {
    if (isEmpty(objectAddr) || isEmpty(memberName)) {
        Logger.showUsage("Set Object Member", "!frame_setattr <addr> <member> <value>", [
            "!frame_setattr 0x1234 \"sandbox_flags_\" \"0x0\"  - LocalFrame member",
            "!frame_setattr 0x1234 \"id\" \"newId\"            - Element DOM attr",
            "!frame_setattr(0x1234, \"host_\", \"evil.com\", \"(blink::SecurityOrigin*)\") - With type hint"
        ]);
        Logger.info("Works with: LocalFrame, Document, LocalDOMWindow, Element, Node, etc.");
        Logger.empty();
        return "";
    }

    var objHex = normalizeAddress(objectAddr);
    var member = memberName.replace(/"/g, "");
    var newValue = value ? value.replace(/"/g, "") : "";
    var typeHintStr = typeHint || null;

    Logger.section("Set Member: " + member);
    Logger.info("Object: " + objHex);
    Logger.info("Target Value: \"" + newValue + "\"");
    Logger.empty();

    // 1. First try DOM attribute (only works for Elements)
    try {
        var implAddr = BlinkUnwrap.findAttributeStringImplAddress(objHex, member);
        if (implAddr && implAddr !== "0") {
            Logger.info("[DOM] Found StringImpl at: " + implAddr);
            MemoryUtils.writeStringImpl(implAddr, newValue);
            Logger.info("[DOM] Attribute value overwritten in memory.");
            Logger.info("Verify with !frame_getattr " + objHex + " \"" + member + "\"");
            Logger.empty();
            return "";
        }
    } catch (e) { /* Not an element */ }

    // 2. Try as C++ member with multi-type fallback (and optional type hint)
    Logger.info("Trying as C++ member...");

    var cppResult = BlinkUnwrap.getCppMemberWithFallback(objHex, member, typeHintStr);
    if (cppResult) {
        Logger.info("[C++] Current value: " + cppResult.value);
        Logger.info("[C++] Type: " + cppResult.type);
        Logger.info("[C++] Via:  " + cppResult.typeCast);

        var success = BlinkUnwrap.setCppMemberWithFallback(objHex, member, newValue, typeHintStr);
        if (success) {
            Logger.info("[C++] Member value written.");
            Logger.info("Verify with !frame_getattr " + objHex + " \"" + member + "\"");
        } else {
            Logger.error("[C++] Failed to write member value.");
            Logger.info("Manual: dx &(" + cppResult.typeCast + objHex + ")->" + member);
            Logger.info("Then use: ed <addr> <value>");
        }
        Logger.empty();
        return "";
    }

    Logger.error("'" + member + "' not found.");
    Logger.info("Use !frame_attrs to list available members.");
    Logger.empty();
    return "";
}

/// =============================================================================
/// PER-FRAME DEVTOOLS COMMANDS
/// =============================================================================

/// Get Document object for frame at index
function frame_document(idx) {
    if (idx === undefined || idx === null || idx === "") {
        Logger.showUsage("Frame Document", "!frame_doc <frame_index>", ["!frame_doc 0", "!frame_doc 1"]);
        Logger.info("Use !frames to list all frames with indices.");
        Logger.empty();
        return "";
    }

    var frameIdx = parseInt(idx);
    var frame = _getFrameByIndex(frameIdx);
    if (!frame) {
        Logger.error("Frame not found at index " + frameIdx + ". Use !frames to list frames.");
        return "";
    }

    Logger.section("Frame Document - Index " + frameIdx);

    var localFrame = BlinkUnwrap.getLocalFrame(frame.webFrame);
    if (!isValidPointer(localFrame)) {
        Logger.error("Could not get LocalFrame from WebLocalFrameImpl");
        return "";
    }
    Logger.info("LocalFrame:      0x" + localFrame);

    var domWindow = BlinkUnwrap.getDomWindow(localFrame);
    if (!isValidPointer(domWindow)) {
        Logger.error("Could not get LocalDOMWindow from LocalFrame");
        return "";
    }
    Logger.info("LocalDOMWindow:  0x" + domWindow);

    var document = BlinkUnwrap.getDocument(domWindow);
    if (!isValidPointer(document)) {
        Logger.error("Could not get Document from LocalDOMWindow");
        return "";
    }
    Logger.info("Document:        0x" + document);

    var url = BlinkUnwrap.getDocumentUrl(document);
    if (url) Logger.info("URL:             " + url);

    Logger.empty();
    Logger.info("Inspect with:");
    Logger.info("  dx ((blink::Document*)0x" + document + ")");
    Logger.info("  dx ((blink::Document*)0x" + document + ")->documentElement()");
    Logger.empty();
    return "0x" + document;
}

/// Get LocalDOMWindow object for frame at index
function frame_window(idx) {
    if (idx === undefined || idx === null || idx === "") {
        Logger.showUsage("Frame Window", "!frame_win <frame_index>", ["!frame_win 0", "!frame_win 1"]);
        Logger.info("Use !frames to list all frames with indices.");
        Logger.empty();
        return "";
    }

    var frameIdx = parseInt(idx);
    var frame = _getFrameByIndex(frameIdx);
    if (!frame) {
        Logger.error("Frame not found at index " + frameIdx + ". Use !frames to list frames.");
        return "";
    }

    Logger.section("Frame Window - Index " + frameIdx);

    var localFrame = BlinkUnwrap.getLocalFrame(frame.webFrame);
    if (!isValidPointer(localFrame)) {
        Logger.error("Could not get LocalFrame from WebLocalFrameImpl");
        return "";
    }
    Logger.info("LocalFrame:      0x" + localFrame);

    var domWindow = BlinkUnwrap.getDomWindow(localFrame);
    if (!isValidPointer(domWindow)) {
        Logger.error("Could not get LocalDOMWindow from LocalFrame");
        return "";
    }
    Logger.info("LocalDOMWindow:  0x" + domWindow);

    Logger.empty();
    Logger.info("Inspect with:");
    Logger.info("  dx ((blink::LocalDOMWindow*)0x" + domWindow + ")");
    Logger.info("  dx ((blink::LocalDOMWindow*)0x" + domWindow + ")->location()");
    Logger.empty();
    return "0x" + domWindow;
}

/// Get SecurityOrigin for frame at index
function frame_origin(idx) {
    if (idx === undefined || idx === null || idx === "") {
        Logger.showUsage("Frame Origin", "!frame_origin <frame_index>", ["!frame_origin 0", "!frame_origin 1"]);
        Logger.info("Use !frames to list all frames with indices.");
        Logger.empty();
        return "";
    }

    var frameIdx = parseInt(idx);
    var frame = _getFrameByIndex(frameIdx);
    if (!frame) {
        Logger.error("Frame not found at index " + frameIdx + ". Use !frames to list frames.");
        return "";
    }

    Logger.section("Frame Origin - Index " + frameIdx);

    var localFrame = BlinkUnwrap.getLocalFrame(frame.webFrame);
    if (!isValidPointer(localFrame)) {
        Logger.error("Could not get LocalFrame from WebLocalFrameImpl");
        return "";
    }

    var domWindow = BlinkUnwrap.getDomWindow(localFrame);
    if (!isValidPointer(domWindow)) {
        Logger.error("Could not get LocalDOMWindow from LocalFrame");
        return "";
    }

    var document = BlinkUnwrap.getDocument(domWindow);
    if (!isValidPointer(document)) {
        Logger.error("Could not get Document from LocalDOMWindow");
        return "";
    }

    var originUrl = BlinkUnwrap.getSecurityOriginUrl(document);
    var docUrl = BlinkUnwrap.getDocumentUrl(document);

    Logger.info("Document:        0x" + document);
    if (docUrl) Logger.info("Document URL:    " + docUrl);
    if (originUrl) Logger.info("Security Origin: " + originUrl);
    else Logger.info("Security Origin: (use dx to inspect)");

    Logger.empty();
    Logger.info("Inspect with:");
    Logger.info("  dx ((blink::Document*)0x" + document + ")->GetExecutionContext()->GetSecurityOrigin()");
    Logger.empty();
    return originUrl || "";
}

/// List elements by tag name in a frame
function frame_elements(idx, tagName) {
    if (idx === undefined || idx === null || idx === "") {
        Logger.showUsage("Frame Elements", "!frame_elem <frame_index> [tag_name]", ["!frame_elem 0", "!frame_elem 0 \"div\"", "!frame_elem 1 \"iframe\""]);
        Logger.info("Use !frames to list all frames with indices.");
        Logger.empty();
        return "";
    }

    var frameIdx = parseInt(idx);
    var frame = _getFrameByIndex(frameIdx);
    if (!frame) {
        Logger.error("Frame not found at index " + frameIdx + ". Use !frames to list frames.");
        return "";
    }

    var filterTag = tagName ? tagName.toLowerCase().replace(/"/g, "") : null;
    Logger.section("Frame Elements - Index " + frameIdx + (filterTag ? " (tag: " + filterTag + ")" : ""));

    var localFrame = BlinkUnwrap.getLocalFrame(frame.webFrame);
    if (!isValidPointer(localFrame)) {
        Logger.error("Could not get LocalFrame from WebLocalFrameImpl");
        return "";
    }

    var document = BlinkUnwrap.getDocumentFromFrame(localFrame);
    if (!isValidPointer(document)) {
        Logger.error("Could not get Document from LocalFrame");
        return "";
    }

    Logger.info("Document: 0x" + document);
    Logger.empty();

    try {
        if (filterTag) {
            Logger.info("Searching for <" + filterTag + "> elements (DOM Walk)...");
            Logger.empty();

            var startNode = BlinkUnwrap.getFirstChild(document);
            if (!startNode || startNode === "0") {
                Logger.info("  Document is empty (no children).");
                return "";
            }

            var stack = [startNode];
            var visited = 0;
            var found = 0;
            var maxNodes = MAX_DOM_TRAVERSAL_NODES;
            var visitedSet = new Set(); // Track visited nodes to prevent infinite loops

            while (stack.length > 0) {
                if (visited > maxNodes) {
                    Logger.warn("  Traversal limit reached (" + maxNodes + " nodes).");
                    break;
                }

                var node = stack.pop();

                // Skip if already visited (prevents infinite loops from corrupted DOM)
                var nodeKey = normalizeAddress(node);
                if (visitedSet.has(nodeKey)) {
                    continue;
                }
                visitedSet.add(nodeKey);
                visited++;

                // Process Node
                var nodeName = BlinkUnwrap.getNodeName(node);

                // Compare case-insensitive
                if (nodeName && nodeName.toLowerCase() === filterTag) {
                    // Extract ID/Class if possible for context? 
                    // For now just address and tag
                    Logger.info("  [" + found + "] 0x" + node + " <" + nodeName + ">");
                    found++;
                }

                // TRAVERSAL: Push Sibling then Child (DFS order: Process child first)
                var sibling = BlinkUnwrap.getNextSibling(node);
                var siblingKey = sibling ? normalizeAddress(sibling) : null;
                if (sibling && sibling !== "0" && siblingKey && !visitedSet.has(siblingKey)) {
                    stack.push(sibling);
                }

                // Only traverse children for ContainerNodes (skip text/comments/doctype)
                // If nodeName is null (unknown), we assume it might have children and try anyway
                if (!nodeName || (nodeName !== "#text" && nodeName !== "#comment" && nodeName !== "#doctype")) {
                    var child = BlinkUnwrap.getFirstChild(node);
                    var childKey = child ? normalizeAddress(child) : null;
                    if (child && child !== "0" && childKey && !visitedSet.has(childKey)) {
                        stack.push(child);
                    }
                }
            }

            if (found === 0) Logger.info("  No <" + filterTag + "> elements found.");
            else Logger.info("  Found " + found + " element(s).");

        } else {
            Logger.info("Document structure:");
            Logger.info("  dx ((blink::Document*)0x" + document + ")->documentElement()");
            Logger.info("  dx ((blink::Document*)0x" + document + ")->body()");
            Logger.info("  dx ((blink::Document*)0x" + document + ")->head()");
            Logger.empty();
            Logger.info("Query elements by tag:");
            Logger.info("  !frame_elem " + frameIdx + " \"div\"");
            Logger.info("  !frame_elem " + frameIdx + " \"iframe\"");
            Logger.info("  !frame_elem " + frameIdx + " \"script\"");
        }
    } catch (e) {
        Logger.error("Error querying elements: " + e.message);
    }

    Logger.empty();
    return "";
}

/// Get a C++ member value from any Blink object (or DOM attribute from Element)
/// @param objectAddr - Address of the object
/// @param memberName - Member name
/// @param typeHint - Optional type hint for non-vtable types (e.g., "(blink::SecurityOrigin*)")
function frame_getattr(objectAddr, memberName, typeHint) {
    if (isEmpty(objectAddr) || isEmpty(memberName)) {
        Logger.showUsage("Get Object Member", "!frame_getattr <addr> <member>", [
            "!frame_getattr 0x1234 \"sandbox_flags_\"  - LocalFrame member",
            "!frame_getattr 0x1234 \"lifecycle_state_\" - Document member",
            "!frame_getattr 0x1234 \"id\"              - Element DOM attr",
            "!frame_getattr(0x1234, \"host_\", \"(blink::SecurityOrigin*)\") - With type hint"
        ]);
        Logger.info("Works with: LocalFrame, Document, LocalDOMWindow, Element, Node, etc.");
        Logger.empty();
        return "";
    }

    var objHex = normalizeAddress(objectAddr);
    var member = memberName.replace(/"/g, "");
    var typeHintStr = typeHint || null;

    Logger.section("Get Member: " + member);
    Logger.info("Object: " + objHex);
    Logger.empty();

    // 1. First try DOM attribute (only works for Elements)
    try {
        var val = BlinkUnwrap.getAttribute(objHex, member);
        if (val !== null) {
            Logger.info("[DOM] " + member + "=\"" + val + "\"");
            return val;
        }
    } catch (e) { /* Not an element */ }

    // 2. Try C++ member with multi-type fallback (and optional type hint)
    var cppResult = BlinkUnwrap.getCppMemberWithFallback(objHex, member, typeHintStr);
    if (cppResult) {
        Logger.info("[C++] " + member + " = " + cppResult.value);
        Logger.info("       Type: " + cppResult.type);
        Logger.info("       Via:  " + cppResult.typeCast);
        return cppResult.value;
    }

    Logger.info("Member not found.");
    Logger.info("Use !frame_attrs to list available members.");
    Logger.empty();
    return "";
}

/// List all attributes of an object (DOM attributes and C++ members)
/// Works with Element, LocalFrame, Document, LocalDOMWindow, etc.
/// @param objectAddr - Address of the object
/// @param debug - Enable debug output
/// @param typeHint - Optional type hint (e.g., "(blink::SecurityOrigin*)") for non-vtable types
function frame_attrs(objectAddr, debug, typeHint) {
    if (isEmpty(objectAddr)) {
        Logger.showUsage("Object Attributes & Members", "!frame_attrs <addr>", [
            "!frame_attrs 0x12345678              - Any Blink object",
            "!frame_attrs(0x12345678, true)       - Enable debug output"
        ]);
        Logger.info("Works with: LocalFrame, Document, LocalDOMWindow, Element, Node, etc.");
        return "";
    }

    var objHex = normalizeAddress(objectAddr);
    var enableDebug = debug === true || debug === "true";
    var typeHintStr = typeHint || null;

    Logger.section("Object Attributes & Members: " + objHex);

    // 1. Try DOM attributes (only works for Elements)
    var attrs = [];
    try {
        BlinkUnwrap._traverseAttributes(objHex, (name, base) => {
            var valStr = BlinkUnwrap._extractAttributeValue(base);
            attrs.push({ name: name, value: valStr || "" });
        }, enableDebug);
    } catch (e) { /* Not an element, skip DOM attrs */ }

    if (attrs.length > 0) {
        Logger.info("[DOM Attributes]");
        for (var a of attrs) {
            Logger.info("  " + a.name + "=\"" + a.value + "\"");
        }
        Logger.empty();
    }

    // 2. List C++ members with multi-type fallback
    Logger.info("[C++ Members]");
    var result = BlinkUnwrap.getCppMembersWithFallback(objHex, enableDebug, typeHintStr);

    if (result.members.length === 0) {
        // Pointer analysis: Try to determine if this address contains a pointer value.
        // Use existing decompression functions for V8/CppGC compressed pointers.
        // If we find a valid pointer, AUTOMATICALLY follow it (recursive call).
        try {
            var val64 = host.memory.readMemoryValues(host.parseInt64(objHex, 16), 1, 8)[0];
            var val64Big = MemoryUtils.parseBigInt(val64);
            var highBits = val64Big >> 32n;
            var val32 = val64Big & 0xFFFFFFFFn;

            if (enableDebug) {
                Logger.info("  [Debug] Raw 64-bit value: 0x" + val64Big.toString(16));
                Logger.info("  [Debug] High 32 bits: 0x" + highBits.toString(16) + ", Low 32 bits: 0x" + val32.toString(16));
            }

            var targetAddr = null;
            var ptrType = null;

            // Case 1: High bits are non-zero - could be a raw 64-bit pointer
            if (highBits !== 0n) {
                var ptrHex = "0x" + val64Big.toString(16);

                // Check if value is in user-mode address range
                if (isValidUserModePointer(val64Big)) {
                    // IMPORTANT: Check if target is a symbol (vtable) - don't follow those
                    // Vtables are in module space, data is in heap space
                    var targetSym = SymbolUtils.getSymbolName(val64Big.toString(16));
                    if (targetSym && (targetSym.indexOf("vftable") !== -1 || targetSym.indexOf("??_7") !== -1)) {
                        if (enableDebug) Logger.info("  [Debug] Target " + ptrHex + " is a vtable symbol, not following.");
                        // This IS an object (first qword is vtable), but we couldn't enumerate members
                        // Don't treat it as a pointer to follow
                    } else {
                        // Verify target is readable
                        try {
                            host.memory.readMemoryValues(host.parseInt64(ptrHex, 16), 1, 8)[0];
                            targetAddr = ptrHex;
                            ptrType = "Raw 64-bit pointer";
                        } catch (readErr) {
                            if (enableDebug) Logger.info("  [Debug] Target " + ptrHex + " not readable.");
                        }
                    }
                }
            }

            // Case 2: High bits are zero - could be compressed pointer
            if (targetAddr === null && highBits === 0n && val32 !== 0n) {
                // Try CppGC decompression first (most common in Blink)
                var cppgcPtr = MemoryUtils.decompressCppgcPtr(val32, objHex);

                if (cppgcPtr && cppgcPtr !== "0") {
                    var testHex = "0x" + cppgcPtr;
                    try {
                        host.memory.readMemoryValues(host.parseInt64(testHex, 16), 1, 8)[0];
                        targetAddr = testHex;
                        ptrType = "Compressed CppGC pointer (Member<T>)";
                    } catch (readErr) {
                        if (enableDebug) Logger.info("  [Debug] CppGC target " + testHex + " not readable.");
                    }
                }

                // Try V8 decompression if CppGC didn't work
                if (targetAddr === null) {
                    var v8Ptr = MemoryUtils.decompressV8Ptr(val32);

                    if (v8Ptr && v8Ptr !== "0") {
                        var testHex = "0x" + v8Ptr;
                        try {
                            host.memory.readMemoryValues(host.parseInt64(testHex, 16), 1, 8)[0];
                            targetAddr = testHex;
                            ptrType = "Compressed V8 pointer";
                        } catch (readErr) {
                            if (enableDebug) Logger.info("  [Debug] V8 target " + testHex + " not readable.");
                        }
                    }
                }
            }

            // If we found a valid pointer target, AUTOMATICALLY follow it
            if (targetAddr !== null) {
                Logger.info("  [" + ptrType + " -> " + targetAddr + "]");
                Logger.empty();
                // Recursive call to inspect the target
                return frame_attrs(targetAddr, debug, typeHintStr);
            }

            // Case 3: NULL pointer
            if (val64Big === 0n) {
                Logger.info("  [NULL pointer]");
            } else {
                // Not a pointer - if we have a typeHint from parent, use it
                if (typeHintStr) {
                    var members = BlinkUnwrap.getCppMembers(objHex, typeHintStr);
                    if (members.length > 0) {
                        Logger.info("  Detected type: " + typeHintStr);
                        Logger.empty();
                        for (var m of members) {
                            var displayVal = m.value;
                            if (displayVal.length > 50) {
                                displayVal = displayVal.substring(0, 47) + "...";
                            }
                            var memberAddr = BlinkUnwrap.getMemberPointer(objHex, typeHintStr, m.name);
                            if (memberAddr && (displayVal === "{...}" || displayVal.indexOf("{...}") !== -1)) {
                                var memberTypeHint = extractPointeeType(m.type);
                                Logger.info("  " + m.name + " -> " + memberAddr + "  !frame_attrs " + memberAddr);
                            } else {
                                Logger.info("  " + m.name + " = " + displayVal + "  !frame_getattr(" + objHex + ", \"" + m.name + "\")");
                            }
                        }
                    } else {
                        Logger.info("  (Type hint " + typeHintStr + " did not match)");
                    }
                } else {
                    // No type hint - cannot determine type
                    Logger.info("  (Type unknown - no vtable, no type hint)");
                    Logger.info("  Provide type: !frame_attrs(" + objHex + ", false, \"(blink::TypeName*)\")");
                }
            }
        } catch (e) {
            Logger.info("  (unable to enumerate members)");
            if (enableDebug) Logger.info("  [Debug] Pointer analysis failed: " + e.message);
        }
    } else {
        Logger.info("  Detected type: " + result.typeCast);
        Logger.empty();

        // Output members with pointer addresses for nested objects
        // Include current type hint in all commands for copy-paste convenience
        var currentTypeHint = result.typeCast;

        for (var m of result.members) {
            var displayVal = m.value;

            // If value is {...} or a complex object, try to get its address
            if (displayVal === "{...}" || displayVal.indexOf("{...}") !== -1) {
                // Get the member's field address
                var memberAddr = BlinkUnwrap.getMemberPointer(objHex, result.typeCast, m.name);
                if (memberAddr) {
                    // Check if this is a pointer type (scoped_refptr<T>, Member<T>, etc.)
                    var memberTypeHint = extractPointeeType(m.type);

                    if (memberTypeHint) {
                        // This is a pointer member - need to dereference to get actual target
                        // Read the 8-byte value at the field address
                        try {
                            var ptrVal = host.memory.readMemoryValues(host.parseInt64(memberAddr, 16), 1, 8)[0];
                            var ptrValBig = MemoryUtils.parseBigInt(ptrVal);

                            if (ptrValBig !== 0n && isValidUserModePointer(ptrValBig)) {
                                var targetAddr = "0x" + ptrValBig.toString(16);
                                Logger.info("  " + m.name + " -> " + targetAddr +
                                    "  !frame_attrs(" + targetAddr + ", false, \"" + memberTypeHint + "\")");
                            } else if (ptrValBig === 0n) {
                                Logger.info("  " + m.name + " = null  !frame_getattr(" + objHex + ", \"" + m.name + "\", \"" + currentTypeHint + "\")");
                            } else {
                                // Might be compressed pointer, show field address with type hint
                                Logger.info("  " + m.name + " -> " + memberAddr +
                                    "  !frame_attrs(" + memberAddr + ", false, \"" + memberTypeHint + "\")");
                            }
                        } catch (e) {
                            // Fallback to field address
                            Logger.info("  " + m.name + " -> " + memberAddr +
                                "  !frame_attrs(" + memberAddr + ", false, \"" + memberTypeHint + "\")");
                        }
                    } else {
                        // Embedded struct - memberAddr IS the object address
                        // Use the member's type directly as the type hint
                        var structType = "(" + m.type + "*)";
                        Logger.info("  " + m.name + " -> " + memberAddr +
                            "  !frame_attrs(" + memberAddr + ", false, \"" + structType + "\")");
                    }
                } else {
                    Logger.info("  " + m.name + " = " + displayVal +
                        "  !frame_getattr(" + objHex + ", \"" + m.name + "\", \"" + currentTypeHint + "\")");
                }
            } else {
                if (displayVal.length > 50) {
                    displayVal = displayVal.substring(0, 47) + "...";
                }
                Logger.info("  " + m.name + " = " + displayVal +
                    "  !frame_getattr(" + objHex + ", \"" + m.name + "\", \"" + currentTypeHint + "\")");
            }
        }
    }

    // Removed global hint since we now have per-line hints
    Logger.empty();
    return "";
}


class ProcessUtils {
    static getCurrentSysId() {
        var pidToSysId = this.getPidToSysIdMap();
        try {
            var currentPid = parseInt(host.currentProcess.Id.toString());
            return pidToSysId.has(currentPid) ? pidToSysId.get(currentPid) : 0;
        } catch (e) { return 0; }
    }

    static parseInfoWithFallback(cmdLine) {
        if (!cmdLine || cmdLine === "") {
            return { type: "renderer", extra: "(sandboxed/locked)" };
        }
        return this.parseInfo(cmdLine);
    }

    static getPidToSysIdMap() {
        var map = new Map();
        try {
            var lines = SymbolUtils.execute("|");
            for (var line of lines) {
                var match = line.toString().match(/(\d+)\s+id:\s*([0-9a-fA-F]+)/);
                if (match) map.set(parseInt(match[2], 16), parseInt(match[1]));
            }
        } catch (e) { }
        return map;
    }

    static getList(filterType) {
        var processes = host.currentSession.Processes;
        var pidToSysId = this.getPidToSysIdMap();
        var results = [];

        // Remember original process to restore after iteration
        var originalId = this.getCurrentSysId();

        for (var proc of processes) {
            try {
                var pid = parseInt(proc.Id.toString());
                var sysId = pidToSysId.has(pid) ? pidToSysId.get(pid) : "?";
                var info = this.getInfoSafe(proc, sysId);

                if (filterType && info.type !== filterType) continue;

                var procObj = {
                    pid: pid,
                    sysId: sysId,
                    type: info.type,
                    extra: info.extra,
                    cmdLine: info.cmdLine,
                    clientId: null
                };

                if (info.type === "renderer" && info.extra) {
                    var clientMatch = info.extra.match(/client=(\d+)/);
                    if (clientMatch) procObj.clientId = clientMatch[1];
                }
                results.push(procObj);
            } catch (e) { }
        }

        // Restore original process context
        try {
            if (originalId !== null && originalId !== 0) {
                SymbolUtils.execute("|" + originalId + "s");
            }
            MemoryUtils.invalidateCaches();
        } catch (e) { }

        return results;
    }

    static getInfoSafe(proc, sysId, skipContextSwitch) {
        var cmdLine = "";
        var readSuccess = false;
        try {
            // Only switch context if not skipped (caller may have already switched)
            if (!skipContextSwitch && sysId !== undefined && sysId !== null && sysId !== "?") {
                try { SymbolUtils.execute("|" + sysId + "s"); } catch (e) { }
            }
            cmdLine = CommandLineUtils.get();
            readSuccess = (cmdLine !== "");
        } catch (e) { }

        if (readSuccess) {
            var info = this.parseInfo(cmdLine);
            return { type: info.type, extra: info.extra, cmdLine: cmdLine, locked: false };
        } else {
            return { type: "renderer", extra: "(sandboxed/locked)", cmdLine: "", locked: true };
        }
    }

    static parseInfo(cmdLine) {
        if (isEmpty(cmdLine)) return { type: "unknown", extra: "" };
        var typeMatch = cmdLine.match(/--type=([^\s"]+)/);
        var extra = "";
        if (typeMatch) {
            var type = typeMatch[1];
            if (type === "renderer") {
                var clientMatch = cmdLine.match(/--renderer-client-id=(\d+)/);
                if (clientMatch) extra = "client=" + clientMatch[1];
            } else if (type === "utility") {
                var utilMatch = cmdLine.match(/--utility-sub-type=([^\s"]+)/);
                if (utilMatch) extra = utilMatch[1].split('.').pop();
            }
            return { type: type, extra: extra };
        }
        if (cmdLine.toLowerCase().indexOf("chrome.exe") !== -1) {
            if (cmdLine.indexOf("--monitor-self") !== -1 || cmdLine.indexOf("crashpad") !== -1) return { type: "crashpad-handler", extra: "" };
            if (cmdLine.indexOf("--enable-features") !== -1 && cmdLine.indexOf("--field-trial-handle") !== -1) return { type: "browser", extra: "" };
            if (cmdLine.length < BROWSER_CMDLINE_MIN_LENGTH || cmdLine.indexOf("--user-data-dir") !== -1) return { type: "browser", extra: "" };
        }
        return { type: "unknown", extra: "" };
    }

    static forEachProcess(filterType, callback) {
        var processes = this.getList(filterType);
        if (processes.length === 0) return 0;

        // Remember original process to restore after iteration
        var originalId = this.getCurrentSysId();
        var count = 0;
        for (var proc of processes) {
            if (proc.sysId === "?" || proc.sysId === null) continue;
            try {
                SymbolUtils.execute("|" + proc.sysId + "s");
                MemoryUtils.invalidateCaches(); // Clear cached cage bases for new process
                var result = callback(proc);
                count++;
                if (result === false) break;
            } catch (e) { Logger.error("Error in process " + proc.pid + ": " + e.message); }
        }
        // Restore original process context
        try {
            if (originalId !== null && originalId !== 0) {
                SymbolUtils.execute("|" + originalId + "s");
            } else {
                SymbolUtils.execute("|0s");
            }
            MemoryUtils.invalidateCaches();
        } catch (e) { }
        return count;
    }

    /// Execute callback in a specific process context, then restore original context
    static withContext(sysId, callback) {
        var originalId = this.getCurrentSysId();
        try {
            SymbolUtils.execute("|" + sysId + "s");
            MemoryUtils.invalidateCaches(); // Clear cached cage bases for new process
            return callback();
        } finally {
            try { SymbolUtils.execute("|" + originalId + "s"); } catch (e) { }
            MemoryUtils.invalidateCaches(); // Clear again when returning to original
        }
    }

    static runInType(targetType, command) {
        // Check current process first
        var currentType = this.parseInfo(CommandLineUtils.get()).type || "renderer"; // heuristic
        if (currentType === targetType) {
            Logger.info("  [" + targetType.toUpperCase() + " PID:" + host.currentProcess.Id + "] Executing: " + command);
            try {
                var output = SymbolUtils.execute(command);
                for (var l of output) Logger.log("  " + l + "\n");
            } catch (e) { Logger.error(e.message); }
            return "executed";
        }

        Logger.section("Running in All " + targetType.toUpperCase() + " Processes");

        var matchCount = this.forEachProcess(targetType, function (info) {
            Logger.info("  [" + targetType.toUpperCase() + " PID:" + info.pid + "] Executing: " + command);
            var output = SymbolUtils.execute(command);
            for (var l of output) Logger.log("    " + l + "\n");
        });

        if (matchCount === 0) {
            Logger.info("  No " + targetType + " processes found.");
            Logger.empty();
            return "no_match";
        }

        Logger.info("  Executed in " + matchCount + " processes");
        Logger.empty();
        return "executed_in_" + matchCount;
    }
}


/// =============================================================================
/// EXECUTION ENGINE (!exec)
/// =============================================================================

class Exec {
    /// Convert value to array of 8 bytes (64-bit Little Endian)
    static _to64BitLE(val) {
        var big = BigInt(val);
        if (big < 0n) big = big + 0x10000000000000000n; // Handle negative
        var bytes = [];
        for (var i = 0; i < 8; i++) {
            bytes.push(Number(big & 0xFFn));
            big >>= 8n;
        }
        return bytes;
    }

    static exec(cmdString) {
        Logger.section("Exec Command");
        if (isEmpty(cmdString)) {
            Logger.showUsage("!exec", '!exec "Target(Args)"', [
                '!exec "chrome!blink::Document::IsSecureContext(0x12345678)"',
                '!exec "0x12345678->MyMethod(10, true)"',
                '!exec "chrome!SomeGlobal(0x123, \\"string arg\\")"'
            ]);
            return;
        }

        // Basic parsing
        var entry = cmdString.trim();
        var parenStart = entry.indexOf('(');
        var parenEnd = entry.lastIndexOf(')');

        if (parenStart === -1 || parenEnd === -1 || parenEnd < parenStart) {
            Logger.error("Invalid format. Expected: Name(Args) or Ptr->Name(Args)");
            return;
        }

        var namePart = entry.substring(0, parenStart).trim();
        var argsPart = entry.substring(parenStart + 1, parenEnd);

        var targetSymbol = namePart;
        var thisPtr = null;

        // Handle 0xAddr->Method(...) syntax
        if (namePart.indexOf("->") !== -1) {
            var parts = namePart.split("->");
            if (parts.length === 2) {
                var ptrPart = parts[0].trim();
                var methodPart = parts[1].trim();

                if (methodPart.indexOf("!") === -1) {
                    // Try to auto-detect type
                    var detectedType = BlinkUnwrap.detectType(ptrPart);
                    if (detectedType) {
                        // detectedType format: (chrome!Class*)
                        var className = detectedType.replace(/[()*]/g, "");
                        targetSymbol = className + "::" + methodPart;
                        Logger.info("  [Auto-Detect] Resolved method: " + targetSymbol);
                    } else {
                        Logger.error("Cannot resolve method '" + methodPart + "' without type information/symbol.");
                        Logger.info("  Provide fully qualified name, e.g., !exec \"0x...->chrome!Class::Method(...)\"");
                        return;
                    }
                } else {
                    targetSymbol = methodPart;
                }
                thisPtr = ptrPart;
            }
        }

        // Resolve Target
        var targetAddr = SymbolUtils.findSymbolAddress(targetSymbol);
        if (!targetAddr) {
            // Try strict address
            if (targetSymbol.startsWith("0x")) targetAddr = targetSymbol;
            else {
                Logger.error("Symbol not found: " + targetSymbol);
                return;
            }
        }

        // Parse Args
        var args = this._parseArgs(argsPart);

        // Prepend 'this' if present
        if (thisPtr) {
            // Treat 'this' as a pointer argument
            args.unshift(this._processArg(thisPtr));
        }

        Logger.info("  Target: " + targetSymbol + " @ " + targetAddr);
        Logger.info("  Args: " + JSON.stringify(args, (k, v) => (typeof v === 'bigint' ? v.toString() : v)));

        // Generate and Run
        this._runX64(targetAddr, args);
    }

    static _parseArgs(argsStr) {
        if (!argsStr || argsStr.trim() === "") return [];
        var args = [];
        var current = "";
        var inQuote = false;

        for (var i = 0; i < argsStr.length; i++) {
            var c = argsStr[i];
            if (c === '"') inQuote = !inQuote;
            else if (c === ',' && !inQuote) {
                args.push(this._processArg(current.trim()));
                current = "";
                continue;
            }
            current += c;
        }
        if (current.trim()) args.push(this._processArg(current.trim()));
        return args;
    }

    static _processArg(arg) {
        // String literal
        if (arg.startsWith('"') && arg.endsWith('"')) {
            return { type: 'string', value: arg.slice(1, -1) };
        }
        // Boolean
        if (arg === 'true') return { type: 'int', value: 1 };
        if (arg === 'false') return { type: 'int', value: 0 };
        // Hex / Number
        if (/^(0x)?[0-9a-fA-F]+$/.test(arg)) {
            return { type: 'int', value: arg };
        }
        // Symbol?
        if (arg.indexOf('!') !== -1) {
            var addr = SymbolUtils.findSymbolAddress(arg);
            if (addr) return { type: 'int', value: addr };
        }

        // Helper: check for 'compressed' syntax? 
        // Assuming simple ints/pointers for now as per plan
        return { type: 'int', value: arg };
    }

    static _runX64(targetAddr, args) {
        // 1. Allocate scratch Memory
        // Need space for: Shellcode + String Data + Result
        var allocSize = 0x1000;
        var baseAddrHex = MemoryUtils.alloc(allocSize);
        if (!baseAddrHex) return;

        var baseAddr = BigInt("0x" + baseAddrHex);

        // Layout:
        // +0x000: Result (8 bytes)
        // +0x010: String Data Start...
        // +0x800: Code Start (Arbitrary safe offset)

        var resultOffset = 0x0n;
        var dataOffset = 0x10n;
        var codeOffset = 0x800n;

        var currentDataOffset = dataOffset;

        // Write String Args
        for (var i = 0; i < args.length; i++) {
            if (args[i].type === 'string') {
                // Convert string to bytes
                var str = args[i].value;
                var bytes = [];
                for (var j = 0; j < str.length; j++) bytes.push(str.charCodeAt(j));
                bytes.push(0); // Null term

                // Write to memory
                var strAddr = baseAddr + currentDataOffset;
                MemoryUtils.writeMemory(strAddr.toString(16), bytes);

                // Update arg value to be the pointer
                args[i].realValue = strAddr;
                currentDataOffset += BigInt(bytes.length);
                // 8-byte align
                if (currentDataOffset % 8n !== 0n) currentDataOffset += (8n - (currentDataOffset % 8n));
            } else {
                // Integer/Pointer
                args[i].realValue = MemoryUtils.parseBigInt(args[i].value);
            }
        }

        // Generate Shellcode
        var code = [];

        // Prologue
        // sub rsp, 0x28 (Shadow space 32 bytes + align) -> Actually just generic shadow space
        // If we push args, we need to balance stack.
        // Stack must be 16-byte aligned BEFORE the CALL instruction.
        // 'int 3' acts as return point.

        // Standard: Shadow space (32 bytes) is required.
        // + stack args.

        var stackArgsCount = (args.length > 4) ? (args.length - 4) : 0;
        var stackSpace = stackArgsCount * 8;
        // Always allocate 0x20 shadow space.
        // Total alloc = 0x20 + stackSpace.
        // Check alignment. 
        // Initial RSP (at breakage) is aligned? Assume WinDbg context.
        // We should align RSP to 16 bytes.

        // Safety: Ensure RSP is 16-byte aligned.
        // and rsp, -16
        code.push(0x48, 0x83, 0xE4, 0xF0); // and rsp, -16

        var totalStack = 0x20 + stackSpace;
        if (totalStack % 16 !== 0) totalStack += 8; // align

        // sub rsp, totalStack
        if (totalStack < 128) {
            code.push(0x48, 0x83, 0xEC, totalStack);
        } else {
            // sub rsp, imm32
            code.push(0x48, 0x81, 0xEC);
            code = code.concat([totalStack & 0xFF, (totalStack >> 8) & 0xFF, 0, 0]);
        }

        // Load Register Args (RCX, RDX, R8, R9)
        var registers = [
            [0x48, 0xB9], // mov rcx, imm64
            [0x48, 0xBA], // mov rdx, imm64
            [0x49, 0xB8], // mov r8, imm64
            [0x49, 0xB9]  // mov r9, imm64
        ];

        for (var i = 0; i < Math.min(args.length, 4); i++) {
            code = code.concat(registers[i]);
            code = code.concat(this._to64BitLE(args[i].realValue));
        }

        // Push Stack Args
        // Args 5+ go to [rsp + 0x20], [rsp + 0x28]...
        // Warning: The space is already allocated (sub rsp). We should MOV them.
        // Because if we PUSH, we mess up offsets relative to shadow space.
        // Correct: mov [rsp + 0x28], arg5

        for (var i = 4; i < args.length; i++) {
            // mov rax, argVal
            code.push(0x48, 0xB8);
            code = code.concat(this._to64BitLE(args[i].realValue));

            // mov [rsp + offset], rax
            var offset = 0x20 + (i - 4) * 8;
            code.push(0x48, 0x89, 0x44, 0x24, offset & 0xFF); // Valid for offset < 128 (approx)
            // Simple encoding limited to byte offset. If offset >= 128 need different opcode?
            // 0x44 is ModR/M byte?
            // 48 89 84 24 [32-bit offset] for larger offsets.
            if (offset >= 0x80) {
                // Fallback to larger offset instruction
                // Replace previous push
                code.pop(); code.pop(); code.pop(); code.pop(); // Undo
                // mov [rsp + disp32], rax
                code.push(0x48, 0x89, 0x84, 0x24);
                code = code.concat([offset & 0xFF, (offset >> 8) & 0xFF, 0, 0]);
            }
        }

        // Call Target
        // mov rax, targetAddr
        code.push(0x48, 0xB8);
        code = code.concat(this._to64BitLE(MemoryUtils.parseBigInt(targetAddr)));
        // call rax
        code.push(0xFF, 0xD0);

        // Save Result
        // mov rbx, resultAddr (pointer to baseAddr)
        code.push(0x48, 0xBB);
        code = code.concat(this._to64BitLE(baseAddr));
        // mov [rbx], rax
        code.push(0x48, 0x89, 0x03);

        // Clean Stack (epilogue)
        if (totalStack < 128) {
            code.push(0x48, 0x83, 0xC4, totalStack);
        } else {
            code.push(0x48, 0x81, 0xC4);
            code = code.concat([totalStack & 0xFF, (totalStack >> 8) & 0xFF, 0, 0]);
        }

        // Break
        code.push(0xCC);

        // Write Code
        var codeAddr = baseAddr + codeOffset;
        MemoryUtils.writeMemory(codeAddr.toString(16), code);

        Logger.info("  Code injected at: 0x" + codeAddr.toString(16));
        Logger.info("  Executing...");

        // Execute via RIP hijacking
        var ctl = SymbolUtils.getControl();

        // Save current registers
        // Using 'r' command to save to psuedo-registers
        ctl.ExecuteCommand("r @$t0 = @rip");
        ctl.ExecuteCommand("r @$t1 = @rsp");
        ctl.ExecuteCommand("r @$t2 = @rcx");
        ctl.ExecuteCommand("r @$t3 = @rdx");
        ctl.ExecuteCommand("r @$t4 = @r8");
        ctl.ExecuteCommand("r @$t5 = @r9");
        ctl.ExecuteCommand("r @$t6 = @rax");

        // Set RIP and Go
        ctl.ExecuteCommand("r @rip = 0x" + codeAddr.toString(16));

        // Run!
        try {
            ctl.ExecuteCommand("g");
        } catch (e) {
            Logger.warn("Execution finished (or break hit).");
        }

        // Read Result
        var resultVals = host.memory.readMemoryValues(host.parseInt64(baseAddr.toString(16), 16), 1, 8);
        var result = resultVals[0];

        // Analyze Result
        this._analyzeResult(result);

        // Restore Registers
        ctl.ExecuteCommand("r @rip = @$t0");
        ctl.ExecuteCommand("r @rsp = @$t1");
        ctl.ExecuteCommand("r @rcx = @$t2");
        ctl.ExecuteCommand("r @rdx = @$t3");
        ctl.ExecuteCommand("r @r8 = @$t4");
        ctl.ExecuteCommand("r @r9 = @$t5");
        ctl.ExecuteCommand("r @rax = @$t6");

        Logger.info("  State restored.");
    }

    static _analyzeResult(result) {
        // Result is BigInt or Host Object
        var val = BigInt(result);
        var hex = val.toString(16);

        Logger.info("  Result (RAX): 0x" + hex);

        // 1. Decimal Values
        Logger.info("    Decimal (Unsigned): " + val.toString(10));

        // Signed interpretation is trickier in JS BigInt without knowing bit-width, assume 64-bit for RAX
        var signed = val;
        if (signed >= 0x8000000000000000n) {
            signed = signed - 0x10000000000000000n;
        }
        Logger.info("    Decimal (Signed):   " + signed.toString(10));

        // 2. String Heuristics (Pointer?)
        // Valid user-mode pointer approx range (0x10000 - 0x7FFFFFFFFFF)
        if (val > 0x10000n && val < 0x7FFFFFFFFFFn) {
            var ptrStr = "0x" + hex;

            // Try reading as ASCII C-String
            try {
                // Read first 50 chars to check for printability
                var ctl = SymbolUtils.getControl();
                var cmd = "da " + ptrStr + " L50";
                var output = ctl.ExecuteCommand(cmd);
                for (var line of output) {
                    // Windbg 'da' output: 00007ff6`...  "Hello World"
                    var m = line.toString().match(/"(.*)"/);
                    if (m) {
                        Logger.info("    String (ASCII):     \"" + m[1] + "\"");
                        // If long, might be truncated, but good enough for typical use
                        break;
                    }
                }
            } catch (e) { }

            // Try reading as UTF-16 Wide-String works similarly with 'du'
            try {
                var cmd = "du " + ptrStr + " L50";
                var output = ctl.ExecuteCommand(cmd);
                for (var line of output) {
                    var m = line.toString().match(/"(.*)"/);
                    if (m) {
                        Logger.info("    String (UTF-16):    \"" + m[1] + "\"");
                        break;
                    }
                }
            } catch (e) { }

            // Check if it looks like a vtable (Symbol check)
            var sym = SymbolUtils.getSymbolName(ptrStr);
            if (sym) {
                Logger.info("    Symbol:             " + sym);
            }
        }
    }
}

/// =============================================================================

function exec_command(cmd) {
    return Exec.exec(cmd);
}

function initializeScript() {
    return [
        new host.apiVersionSupport(1, 7),
        // Exec
        new host.functionAlias(exec_command, "exec"),
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
        new host.functionAlias(on_process_exit, "on_process_exit"),
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
        new host.functionAlias(decompress_gc, "decompress_gc"),
        // Site Isolation
        new host.functionAlias(site_isolation_status, "site_iso"),
        // Mojo Interface Introspection
        new host.functionAlias(mojo_interfaces, "mojo_interfaces"),
        // Per-Frame DOM Inspection
        new host.functionAlias(frame_document, "frame_doc"),
        new host.functionAlias(frame_window, "frame_win"),
        new host.functionAlias(frame_origin, "frame_origin"),
        new host.functionAlias(frame_elements, "frame_elem"),
        new host.functionAlias(frame_getattr, "frame_getattr"),
        new host.functionAlias(frame_setattr, "frame_setattr"),
        new host.functionAlias(frame_attrs, "frame_attrs"),

        // Cache Management
        new host.functionAlias(cache_clear, "cache_clear")
    ];
}

/// Clean up global state when script is unloaded (prevents issues on reload)
function uninitializeScript() {
    // Reset global state to prevent stale data on script reload
    g_rendererAttachCommands = [];
    g_spoofMap.clear();
    g_exitHandlerRegistered = false;

    // Invalidate cached memory addresses
    GlobalCache.clearAll();
}

/// Initialize the Chrome debugging environment
function chrome_init() {
    Logger.header("Chromium Security Research Debugger - Initialized");
    Logger.info("Type !chelp for available commands");
    Logger.empty();

    // Set up useful aliases
    try {
        var ctl = SymbolUtils.getControl();
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
    Logger.section("Chromium Security Research Debugger - Commands");

    Logger.info("PROCESS IDENTIFICATION:");
    Logger.info("  !proc                 - Show process type (+ site if renderer)");
    Logger.info("  !cmdline              - Show the command line for the current process");
    Logger.info("  !procs                - List all Chrome processes with types");
    Logger.info("  !frames               - List all frames in current renderer process");
    Logger.empty();

    Logger.info("SANDBOX & SECURITY:");
    Logger.info("  !sandbox_all          - Dashboard of sandbox status for ALL processes");
    Logger.info("  !sandbox_state        - Check sandbox status of CURRENT process");
    Logger.info("  !sandbox_token        - Dump process token info and integrity level");
    Logger.empty();

    Logger.info("SECURITY BREAKPOINTS:");
    Logger.info("  !bp_renderer          - Break when renderer processes are launched");
    Logger.info("  !bp_sandbox           - Break when sandbox lowers token");
    Logger.info("  !bp_mojo              - Break on Mojo interface binding");
    Logger.info("  !bp_ipc               - Break on IPC message dispatch");
    Logger.info("  !bp_bad               - Break on mojo::ReportBadMessage (security violations!)");
    Logger.info("  !bp_security          - Break on ChildProcessSecurityPolicy checks");
    Logger.info("  !trace_ipc            - Enable IPC message logging (noisy)");
    Logger.info("  !mojo_interfaces      - List mojo interfaces exposed to current renderer");
    Logger.empty();

    Logger.info("VULNERABILITY HUNTING:");
    Logger.info("  !vuln_hunt            - UAF, type confusion, race condition breakpoints");
    Logger.info("  !heap_info            - PartitionAlloc/V8 heap inspection guide");
    Logger.empty();

    Logger.info("ORIGIN SPOOFING & FUNCTION PATCHING (renderer only):");
    Logger.info("  !spoof(\"url\")                       - Spoof origin by patching memory");
    Logger.info("  !patch(\"FullscreenIsSupported\",\"false\") - Patch function (auto-inlining detection)");
    Logger.empty();

    Logger.info("BLINK DOM HOOKS:");
    Logger.info("  !blink_help           - Show full Blink DOM help");
    Logger.info("  !bp_element           - Break on DOM element creation");
    Logger.info("  !bp_nav               - Break on navigation");
    Logger.info("  !bp_pm                - Break on postMessage");
    Logger.info("  !bp_fetch             - Break on Fetch/XHR");
    Logger.empty();

    Logger.info("PER-FRAME INSPECTION (DOM attrs + C++ members):");
    Logger.info("  !frame_doc(idx)       - Get Document for frame at index");
    Logger.info("  !frame_win(idx)       - Get LocalDOMWindow for frame at index");
    Logger.info("  !frame_origin(idx)    - Get SecurityOrigin for frame at index");
    Logger.info("  !frame_elem(idx,tag)  - List elements by tag name in frame");
    Logger.info("  !frame_getattr(el,a)  - Get DOM attribute OR C++ member (auto-detect)");
    Logger.info("  !frame_setattr(el,a,v)- Set DOM attribute OR C++ member (auto-detect)");
    Logger.info("  !frame_attrs(el)      - List all DOM attributes AND C++ members");
    Logger.empty();

    Logger.info("V8 EXPLOITATION HOOKS:");
    Logger.info("  !v8_help              - Show full V8 help");
    Logger.info("  !bp_compile           - Break on script compilation");
    Logger.info("  !bp_gc                - Break on Garbage Collection");
    Logger.info("  !bp_wasm              - Break on WebAssembly");
    Logger.info("  !bp_jit               - Break on JIT compilation");
    Logger.empty();

    Logger.info("V8 POINTER COMPRESSION:");
    Logger.info("  !v8_cage              - Show V8 cage base address");
    Logger.info("  !decompress(ptr)      - Decompress a 32-bit V8 compressed pointer");
    Logger.empty();

    Logger.info("PROCESS-SPECIFIC EXECUTION (works from any process):");
    Logger.info("  !run_renderer(\"cmd\")      - Run command in all renderer processes");
    Logger.info("  !run_browser(\"cmd\")       - Run command in browser process");
    Logger.info("  !run_gpu(\"cmd\")           - Run command in GPU process");
    Logger.info("  !script_renderer(\"path\")  - Load script in all renderers");
    Logger.info("  !on_attach(\"cmd\")         - Auto-run command when renderers attach");
    Logger.info("  !script_attach(\"path\")    - Auto-load script when renderers attach");
    Logger.empty();

    Logger.info("TIPS:");
    Logger.info("  - Use '|' to switch between processes: |0s, |1s, etc.");
    Logger.info("  - Use '||' to list all debugged processes");
    Logger.info("  - Use '~*k' to get stacks from all threads");
    Logger.empty();
    return "";
}

function cache_clear() {
    GlobalCache.clearAll();
    Logger.info("Global security script cache cleared.");
    return "";
}

/// =============================================================================
/// INTERNAL HELPERS
/// =============================================================================

/// Display cage base info for both V8 and cppgc/Oilpan
function v8_cage_info() {
    Logger.section("Pointer Compression Cages");

    var v8CageBase = MemoryUtils.getV8CageBase();
    if (v8CageBase) {
        Logger.info("V8 Cage Base:     0x" + v8CageBase);
        Logger.info("  Formula: Full = CageBase + SignExtend32(Compressed)");
    } else {
        Logger.info("V8 Cage Base:     (not found)");
    }
    Logger.empty();

    var cppgcCageBase = MemoryUtils.getCppgcCageBase();
    if (cppgcCageBase) {
        Logger.info("Oilpan Cage Base: 0x" + cppgcCageBase);
        Logger.info("  Formula: Full = (SignExtend32(Compressed) << 1) & Base");
    } else {
        Logger.info("Oilpan Cage Base: (not found)");
    }
    Logger.empty();

    Logger.info("Commands:");
    Logger.info("  !decompress <ptr>      - V8 decompression");
    Logger.info("  !decompress_gc <ptr>   - Oilpan/cppgc decompression");
    Logger.empty();

    return "";
}

/// Decompress command - exposed to user
function decompress(ptr) {
    if (isEmpty(ptr)) {
        Logger.showUsage(
            "V8 Pointer Decompression",
            "!decompress <compressed_ptr>",
            ["!decompress 0x12345678"]
        );
        return "";
    }

    var result = MemoryUtils.decompressV8Ptr(ptr);
    if (result) {
        Logger.empty();
        Logger.info("Compressed: " + ptr);
        Logger.info("Full ptr:   0x" + result);
        Logger.empty();
    } else {
        Logger.empty();
        Logger.warn("Could not decompress - cage base not found.");
        Logger.info("Try !v8_cage to see cage info.");
        Logger.empty();
    }
    return "";
}

/// Decompress Oilpan/cppgc pointer - exposed to user
function decompress_gc(ptr) {
    if (isEmpty(ptr)) {
        Logger.showUsage(
            "Oilpan/cppgc Pointer Decompression",
            "!decompress_gc <compressed_ptr>",
            ["!decompress_gc 0x12345678", "Used for blink::Member<T>, cppgc::internal::BasicMember<T>"]
        );
        return "";
    }

    var result = MemoryUtils.decompressCppgcPtr(ptr);

    if (result === null) {
        Logger.empty();
        Logger.warn("Could not decompress - cage base not found.");
        Logger.info("Try !decompress_gc <ptr> <context_address> to derive base from an object.");
        Logger.empty();
    } else {
        Logger.empty();
        Logger.info("Compressed: " + ptr);
        Logger.info("Full ptr:   0x" + result);
        Logger.empty();
    }
    return "";
}


/// Helper: Set multiple breakpoints with a title and description
function set_breakpoints(title, targets, description) {
    BreakpointManager.set(title, targets, description);
    return "";
}


/// Helper: Find the browser process System ID
function get_browser_sysid() {
    var processes = host.currentSession.Processes;
    var pidToSysId = ProcessUtils.getPidToSysIdMap();

    // Remember original process to restore after searching
    var originalId = ProcessUtils.getCurrentSysId();
    var result = null;

    for (var proc of processes) {
        var pid = parseInt(proc.Id.toString());
        if (pidToSysId.has(pid)) {
            var sysId = pidToSysId.get(pid);
            var info = ProcessUtils.getInfoSafe(proc, sysId);
            if (info.type === "browser") {
                result = sysId;
                break;
            }
        }
    }

    // Restore original process context
    try {
        if (originalId !== null && originalId !== 0) {
            SymbolUtils.execute("|" + originalId + "s");
        }
        MemoryUtils.invalidateCaches();
    } catch (e) { }

    return result;
}

/// Helper: Get map of Renderer Client ID -> Site Lock URL
/// Uses GetProcessLock to query each child ID individually.
/// @param browserSysId - WinDbg system ID for the browser process
/// @param childIds - Array of child IDs to query (from command line parsing)
function get_site_locks(browserSysId, childIds) {
    var locks = new Map();
    var ctl = SymbolUtils.getControl();

    if (browserSysId === null || !childIds || childIds.length === 0) {
        return locks;
    }

    // Remember original process to restore after querying
    var originalId = ProcessUtils.getCurrentSysId();

    try {
        // Step 1: Get the GetInstance symbol address
        var funcAddr = null;
        try {
            var xOutput = ctl.ExecuteCommand("x chrome!content::ChildProcessSecurityPolicyImpl::GetInstance");
            for (var xLine of xOutput) {
                var addr = SymbolUtils.extractAddress(xLine);
                if (addr) {
                    funcAddr = addr;
                    break;
                }
            }
        } catch (xErr) { /* continue with null funcAddr */ }

        if (!funcAddr) {
            // Early exit - will restore in finally
            return locks;
        }

        // Step 2: Find a browser with chrome.dll and accessible singleton
        var instanceAddr = null;
        var workingBrowserId = null;

        ProcessUtils.forEachProcess("browser", function (proc) {
            try {
                // Check if chrome is loaded in this browser
                var lmOut = SymbolUtils.execute("lm m chrome");
                var hasChrome = false;
                for (var lmLine of lmOut) {
                    var lmStr = lmLine.toString();
                    if (lmStr.indexOf("chrome") !== -1 && lmStr.indexOf("start") === -1 && lmStr.indexOf("Browse") === -1) {
                        hasChrome = true;
                        break;
                    }
                }

                if (!hasChrome) return;

                // Use poi() to read the singleton pointer from the correct process context
                var disasm = SymbolUtils.execute("u " + funcAddr + " L15");
                for (var dLine of disasm) {
                    var dLineStr = dLine.toString();
                    var addrMatch = dLineStr.match(/\(([0-9a-fA-F`]+)\)\]/);
                    if (addrMatch) {
                        var addrStr = addrMatch[1].replace(/`/g, "");
                        try {
                            var poiOut = SymbolUtils.execute("? poi(0x" + addrStr + ")");
                            for (var poiLine of poiOut) {
                                var poiMatch = poiLine.toString().match(/= ([0-9a-fA-F`]+)/);
                                if (poiMatch) {
                                    var ptrVal = poiMatch[1].replace(/`/g, "");
                                    if (isValidPointer(ptrVal) && ptrVal.length > MIN_PTR_VALUE_LENGTH) {
                                        var candidateAddr = "0x" + ptrVal;

                                        // Verify memory is accessible
                                        var memoryOk = false;
                                        try {
                                            var dqsCheck = SymbolUtils.execute("dqs " + candidateAddr + " L1");
                                            for (var dqsLine of dqsCheck) {
                                                var dqsStr = dqsLine.toString();
                                                if (dqsStr.indexOf("????????") === -1 && dqsStr.indexOf(ptrVal.substring(0, 8)) !== -1) {
                                                    memoryOk = true;
                                                }
                                            }
                                        } catch (e) { }

                                        if (memoryOk) {
                                            instanceAddr = candidateAddr;
                                            workingBrowserId = proc.sysId;
                                            return false; // Break loop
                                        }
                                    }
                                }
                            }
                        } catch (e) { }
                        if (instanceAddr) return false;
                    }
                }
            } catch (e) { }
        });

        if (!instanceAddr) {
            // Early exit - will restore in finally
            return locks;
        }

        // Step 3: Switch to browser context for dx command
        try {
            SymbolUtils.execute("|" + workingBrowserId + "s");
            MemoryUtils.invalidateCaches();
        } catch (e) { }

        // Step 4: Enumerate all entries in security_state_ map
        try {
            var enumCmd = "dx -r6 ((chrome!content::ChildProcessSecurityPolicyImpl*)" + instanceAddr + ")->security_state_";

            var enumOutput = ctl.ExecuteCommand(enumCmd);
            var currentChildId = null;
            var currentLockUrl = null;

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
                    var extractedUrl = extractUrlFromLine(lineStr);
                    if (extractedUrl && currentChildId !== null) {
                        currentLockUrl = extractedUrl;
                    }
                }

            }

            // Save last entry
            if (currentChildId !== null && currentLockUrl !== null) {
                locks.set(currentChildId.toString(), currentLockUrl);
            }
        } catch (e) { }

        return locks;
    } finally {
        // Always restore original process context
        try {
            if (originalId !== null && originalId !== 0) {
                SymbolUtils.execute("|" + originalId + "s");
            }
            MemoryUtils.invalidateCaches();
        } catch (e) { }
    }
}


/// =============================================================================
/// PROCESS IDENTIFICATION
/// =============================================================================

/// Get the command line for the current process (alias for CommandLineUtils.get)
var getCommandLine = CommandLineUtils.get.bind(CommandLineUtils);

/// Identify the current Chrome process type (and site if renderer)
function chrome_process_type() {
    var cmdLine = getCommandLine();
    var info = ProcessUtils.parseInfoWithFallback(cmdLine);

    var pid = host.currentProcess.Id;
    var pidVal = parseInt(pid.toString());

    Logger.empty();
    Logger.info("PID:  " + pidVal);
    Logger.info("Type: " + info.type);
    if (info.extra) {
        Logger.info(" (" + info.extra + ")");
    }
    Logger.empty();

    // If renderer, also show the locked site
    if (info.type === "renderer") {
        try {
            renderer_site(); // Prints site info directly
        } catch (e) { Logger.debug("renderer_site failed: " + e.message); }
    }

    return info.type;
}

/// Display parsed command line switches
function chrome_cmdline() {
    var cmdLine = getCommandLine();

    if (isEmpty(cmdLine)) {
        return "Unable to read command line (process may be sandboxed/locked)";
    }

    Logger.section("Chrome Command Line");

    // Parse switches
    var switches = CommandLineUtils.parseSwitches(cmdLine);

    // Categorize and display
    var securitySwitches = ["no-sandbox", "disable-web-security", "disable-site-isolation-trials",
        "site-per-process", "disable-features", "enable-features"];
    var processSwitches = ["type", "renderer-client-id", "utility-sub-type", "field-trial-handle"];

    Logger.info("Security-Relevant Switches:");
    Logger.info("-".repeat(60));
    Logger.displaySwitches(switches, securitySwitches);

    Logger.info("Process Switches:");
    Logger.info("-".repeat(60));
    Logger.displaySwitches(switches, processSwitches);

    Logger.info("Full command line:");
    Logger.info(cmdLine.substring(0, CMDLINE_DISPLAY_LENGTH) + "...");
    Logger.empty();

    return "";
}


/// List all Chrome processes in the debug session with site isolation info
function chrome_processes() {
    Logger.section("Chrome Processes in Debug Session");

    var ctl = SymbolUtils.getControl();

    // 1. Get List using helper
    var processInfoList = ProcessUtils.getList();
    var pidToSysId = ProcessUtils.getPidToSysIdMap();

    // Remember which process we're currently in
    var originalId = ProcessUtils.getCurrentSysId();

    // 2. Find browser process
    var browserSysId = null;
    var browserCmdLine = "";

    for (var pInfo of processInfoList) {
        if (pInfo.type === "browser") {
            browserSysId = pInfo.sysId;
            browserCmdLine = pInfo.cmdLine;
            break;
        }
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

    Logger.info("[Site Isolation] ");
    if (disableSI) {
        Logger.info("DISABLED (--disable-site-isolation)");
    } else if (sitePerProcess) {
        Logger.info("ENABLED (--site-per-process)");
    } else if (isolateOrigins) {
        Logger.info("PARTIAL (--isolate-origins)");
    } else {
        Logger.info("Default");
    }
    Logger.empty();

    // 6. Display process list with site info inline
    Logger.info("  ID    PID       Type            Site / Extra Info");
    Logger.info("  " + "-".repeat(70));

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
            // Check for spoofing
            if (g_spoofMap.has(pInfo.clientId)) {
                displayExtra += " [SPOOFED: " + g_spoofMap.get(pInfo.clientId).currentUrl + "]";
            }
        }

        var sysIdStr = pInfo.sysId !== null ? pInfo.sysId.toString() : "?";
        Logger.info("  " + sysIdStr.padEnd(6) +
            pInfo.pid.toString().padEnd(10) +
            pInfo.type.padEnd(16) +
            displayExtra);
    }

    // Switch back to original process
    try {
        if (originalId !== null && originalId !== 0) ctl.ExecuteCommand("|" + originalId + "s");
    } catch (e) { }

    Logger.empty();
    Logger.info("Use |<ID>s to switch to a process (e.g., |1s)");
    Logger.empty();
    return "";
}

/// Show the locked site for the current renderer process
function renderer_site() {
    var ctl = SymbolUtils.getControl();

    // Get current process info
    var cmdLine = getCommandLine();
    var info = ProcessUtils.parseInfoWithFallback(cmdLine);

    if (info.type !== "renderer") {
        Logger.info("  Not a renderer process (current: " + info.type + ")");
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
        Logger.info("  Unable to determine renderer client ID");
        return "";
    }

    // Remember current process
    var originalId = ProcessUtils.getCurrentSysId();

    // Find browser process
    var browserSysId = get_browser_sysid();

    if (browserSysId === null) {
        Logger.info("  Unable to find browser process");
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

    Logger.empty();
    Logger.info("  Renderer Client ID: " + clientId);
    if (g_spoofMap.has(clientId)) {
        Logger.info("  Locked Site:        " + site + " (Browser)");
        Logger.info("  Spoofed Site:       " + g_spoofMap.get(clientId).currentUrl + " (Active)");
    } else {
        Logger.info("  Locked Site:        " + site);
    }
    Logger.empty();

    return site;
}

/// =============================================================================
/// MOJO INTERFACE INTROSPECTION
/// =============================================================================

/// List mojo interfaces exposed to the current renderer process
/// Requires running from a renderer, switches to browser to read BinderMap
function mojo_interfaces() {
    Logger.section("Mojo Interfaces Exposed to Renderer");

    var ctl = SymbolUtils.getControl();

    // 1. Verify we're in a renderer
    var cmdLine = getCommandLine();
    var info = ProcessUtils.parseInfoWithFallback(cmdLine);

    if (info.type !== "renderer") {
        Logger.warn("This command must be run from a renderer process.");
        Logger.info("Current process type: " + info.type);
        Logger.empty();
        Logger.info("Use !procs to list processes, then |<id>s to switch to a renderer.");
        Logger.empty();
        return "";
    }

    // 2. Get renderer client ID
    var clientId = null;
    if (cmdLine) {
        var clientMatch = cmdLine.match(/--renderer-client-id=(\d+)/);
        if (clientMatch) clientId = clientMatch[1];
    }

    if (!clientId) {
        Logger.warn("Could not determine renderer client ID.");
        Logger.empty();
        return "";
    }

    Logger.info("Renderer Client ID: " + clientId);
    Logger.empty();

    // 3. Remember current process to restore later  
    var originalId = ProcessUtils.getCurrentSysId();

    // Save renderer PID BEFORE switching context
    var rendererPid = host.currentProcess.Id;

    // 4. Find browser process
    var browserSysId = get_browser_sysid();
    if (browserSysId === null) {
        Logger.warn("Could not find browser process.");
        Logger.empty();
        return "";
    }

    var interfaces = [];

    try {
        // 5. Switch to browser process
        SymbolUtils.execute("|" + browserSysId + "s");

        Logger.info("Querying interface binders from browser process...");
        Logger.info("Filtering for renderer client ID: " + clientId + " (PID: " + rendererPid + ")");
        Logger.empty();

        // 6. Find RenderFrameHostImpl for this renderer and read its binder maps
        // Structure: g_routing_id_frame_map -> flat_hash_map<GlobalRenderFrameHostId, RenderFrameHostImpl*>
        // GlobalRenderFrameHostId contains child_id (ChildProcessId) which maps to renderer-client-id
        // RenderFrameHostImpl -> broker_holder_ -> broker_ -> binder_map_ -> binders_

        // Use SymbolUtils for cached symbol lookup
        var frameMapAddr = SymbolUtils.findSymbolAddress("chrome!*g_routing_id_frame_map*");

        if (!frameMapAddr) {
            Logger.warn("Could not find g_routing_id_frame_map symbol.");
            Logger.info("Try: .reload /f chrome.dll");
            Logger.empty();
            return "";
        }

        Logger.info("g_routing_id_frame_map (LazyInstance) at: 0x" + frameMapAddr);

        // Read the LazyInstance::private_instance_ pointer to get actual map address
        var mapPtr = null;
        try {
            var lazyAddrVal = BigInt("0x" + frameMapAddr);
            var ptrValue = host.memory.readMemoryValues(host.parseInt64(lazyAddrVal.toString(16), 16), 1, 8)[0];
            mapPtr = ptrValue.toString(16);
        } catch (e) {
            Logger.warn("Failed to read LazyInstance pointer: " + e.message);
        }

        if (!mapPtr || mapPtr === "0") {
            Logger.warn("LazyInstance not initialized or map pointer is null.");
            Logger.empty();
            return "";
        }

        Logger.info("RoutingIDFrameMap at: 0x" + mapPtr);
        Logger.empty();

        // Enumerate the flat_hash_map to find RenderFrameHostImpl pointers
        // Filter to only those matching our renderer's client ID
        var rfhAddresses = [];
        try {
            // Cast the actual map pointer (not the LazyInstance wrapper)
            var dxCmd = "dx -r5 (*((content::`anonymous namespace'::RoutingIDFrameMap*)0x" + mapPtr + "))";
            var dxOutput = ctl.ExecuteCommand(dxCmd);

            var currentProcessId = null;
            for (var line of dxOutput) {
                var lineStr = line.toString();

                // Look for child_id in the GlobalRenderFrameHostId key
                // Format varies - try multiple patterns
                var processIdMatch = lineStr.match(/child_id_.*?id_\s*[=:]\s*(\d+)/i) ||
                    lineStr.match(/child_id\s*[=:]\s*(\d+)/i) ||
                    lineStr.match(/process_id.*?[=:]\s*(\d+)/i);
                if (processIdMatch) {
                    currentProcessId = processIdMatch[1];
                }

                // Look for RenderFrameHostImpl* values 
                var rfhMatch = lineStr.match(/second\s*[=:]\s*(0x[0-9a-fA-F`]+)/i) ||
                    lineStr.match(/RenderFrameHostImpl\s*\*?\s*[=:]\s*(0x[0-9a-fA-F`]+)/i);
                if (rfhMatch) {
                    var rfhAddr = rfhMatch[1].replace(/`/g, "");

                    // Filter: only include RFHIs from our renderer (matching client ID)
                    if (rfhAddr !== "0x0" && rfhAddr !== "0" && currentProcessId === clientId) {
                        rfhAddresses.push(rfhAddr);
                    }
                    currentProcessId = null; // Reset for next entry
                }
            }
        } catch (e) {
            // Map enumeration failed
        }

        Logger.info("Found " + rfhAddresses.length + " RenderFrameHostImpl(s) for this renderer");
        Logger.empty();

        // For each RFH, read the broker's binder maps
        var foundInterfaces = new Map();

        for (var rfhAddr of rfhAddresses) {
            try {
                // Read broker binder map interfaces
                // Path: rfh->broker_holder_->broker_->binder_map_->binders_

                // Use deep recursion to find all interface names in the broker structure
                var binderCmd = "dx -r6 ((content::RenderFrameHostImpl*)" + rfhAddr + ")->broker_holder_";
                var binderOutput = ctl.ExecuteCommand(binderCmd);

                for (var bLine of binderOutput) {
                    var bStr = bLine.toString();

                    // Capture ANY quoted string containing ".mojom." - don't be restrictive
                    // This ensures we don't miss interfaces with unusual naming patterns
                    var matches = bStr.match(/"([^"]*\.mojom\.[^"]+)"/g);
                    if (matches) {
                        for (var m of matches) {
                            var ifaceName = m.replace(/"/g, "");
                            foundInterfaces.set(ifaceName, true);
                        }
                    }
                }

            } catch (rfhErr) {
                // May fail for some RFHIs, continue
            }
        }

        // Convert Map keys to array
        interfaces = Array.from(foundInterfaces.keys()).sort();

    } finally {
        // 7. Always restore original process context
        try {
            if (originalId !== null && originalId !== 0) {
                SymbolUtils.execute("|" + originalId + "s");
            }
        } catch (e) { }
    }

    // 8. Display results
    if (interfaces.length === 0) {
        Logger.info("No interfaces found.");
        Logger.empty();
        return "";
    }

    Logger.info("Found " + interfaces.length + " mojo interface(s) exposed to renderer:");
    Logger.info("-".repeat(70));
    Logger.empty();

    // Group by namespace
    var byNamespace = new Map();
    for (var iface of interfaces) {
        var dotIdx = iface.lastIndexOf(".");
        var ns = dotIdx > 0 ? iface.substring(0, dotIdx) : "(unknown)";
        if (!byNamespace.has(ns)) {
            byNamespace.set(ns, []);
        }
        byNamespace.get(ns).push(iface);
    }

    // Display grouped
    for (var entry of byNamespace) {
        var namespace = entry[0];
        var ifaces = entry[1];

        Logger.info("  " + namespace + " (" + ifaces.length + " interfaces):");

        for (var iface of ifaces) {
            var className = iface.substring(iface.lastIndexOf(".") + 1);
            Logger.info("    - " + className);
        }
        Logger.empty();
    }

    Logger.info("Total: " + interfaces.length + " interfaces");
    Logger.empty();

    Logger.info("Chromium Source Reference:");
    Logger.info("  https://source.chromium.org/chromium/chromium/src/+/main:content/browser/browser_interface_binders.cc");
    Logger.empty();

    Logger.info("To find .mojom file for an interface:");
    Logger.info("  https://source.chromium.org/search?q=<interface_name>.mojom");
    Logger.empty();

    return "";
}

/// =============================================================================
/// FUNCTION PATCHING & ORIGIN SPOOFING
/// =============================================================================

/// Patch a function to return a specific value
/// Usage: !patch_function "FunctionName" "return_value"
function patch_function(funcName, returnValue) {
    Logger.section("Patch Function");

    if (isEmpty(funcName)) {
        Logger.info("  Usage: !patch(\"ClassName::FunctionName\",\"value\")");
        Logger.info("  Values: true, false, 0, 1, 0x1234, or any number");
        Logger.info("  Examples:");
        Logger.info("    !patch(\"FullscreenIsSupported\",\"false\")");
        Logger.info("    !patch(\"IsFeatureEnabled\",\"0\")");
        Logger.info("    !patch(\"*CanAccess*\",\"true\")");
        Logger.empty();
        Logger.info("  Auto-detects inlining and patches callers if needed.");
        Logger.empty();
        return "";
    }

    // Architecture Check
    try {
        var ctl = SymbolUtils.getControl();
        var session = host.currentSession;
        // Check effective machine. 0x8664 is AMD64/x64.
        // We can also check attributes on current process or target.
        // Simple heuristic: check pointer size or .effmach
        var isX64 = false;
        var out = ctl.ExecuteCommand(".effmach");
        for (var line of out) {
            if (line.toString().toLowerCase().indexOf("x64") !== -1 || line.toString().indexOf("AMD64") !== -1) {
                isX64 = true;
                break;
            }
        }

        if (!isX64) {
            Logger.error("Patching is currently only supported on x64 architectures.");
            Logger.error("Your current effective machine does not appear to be x64.");
            return "";
        }
    } catch (e) {
        // Fallback: proceed with caution if check fails
    }

    // ctl already declared above in architecture check, reuse it

    // Parse return value - support true/false/hex/decimal
    var retVal = 0;
    if (isEmpty(returnValue)) {
        retVal = 0;
    } else if (typeof returnValue === "boolean") {
        retVal = returnValue ? 1 : 0;
    } else if (returnValue === "true" || returnValue === "TRUE" || returnValue === "True") {
        retVal = 1;
    } else if (returnValue === "false" || returnValue === "FALSE" || returnValue === "False") {
        retVal = 0;
    } else if (returnValue.toString().startsWith("0x") || returnValue.toString().startsWith("0X")) {
        retVal = parseInt(returnValue, 16);
    } else {
        retVal = parseInt(returnValue) || 0;
    }

    // String Support: If returnValue is a string that wasn't parsed as hex/bool
    // or if the user explicitly provided a quoted string that resulted in 0/NaN
    if (typeof returnValue === "string" && !returnValue.toString().startsWith("0x") &&
        returnValue !== "true" && returnValue !== "false" && isNaN(parseInt(returnValue))) {

        Logger.info("  Detected string input: \"" + returnValue + "\"");
        var strLen = returnValue.length;
        // Allocate memory for the string (plus null terminator)
        // If 64-bit, we might want to align, but dvalloc usually page-aligns or 16-byte aligns.
        // We'll treat it as a raw C-string (const char*).
        var allocAddr = MemoryUtils.alloc(strLen + 1);

        if (allocAddr) {
            Logger.info("  Allocated memory for string at: 0x" + allocAddr);

            // Write string bytes
            var bytes = [];
            for (var i = 0; i < strLen; i++) {
                bytes.push(returnValue.charCodeAt(i) & 0xFF);
            }
            bytes.push(0); // Null terminator

            MemoryUtils.writeMemory(allocAddr, bytes);

            // Set return value to the address of the string
            retVal = BigInt("0x" + allocAddr);
            Logger.info("  Patching function to return pointer: 0x" + allocAddr);
        } else {
            Logger.error("  Failed to allocate memory for string. Aborting patch.");
            return "";
        }
    }

    Logger.info("  Return value: " + retVal.toString(16) + (retVal === 0 ? " (false)" : retVal === 1 ? " (true)" : ""));
    Logger.empty();

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
            Logger.info("  Searching for: *" + funcName + "*");
            Logger.empty();

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
            Logger.info("  No matching symbols found.");
            Logger.empty();
            return "";
        }

        Logger.info("  Found " + symbols.length + " symbol(s):");
        Logger.empty();

        // Direct code patching: write "mov eax, VALUE; ret" at function start
        // This is more reliable than breakpoints for getters/inlined code
        // x64: mov eax, imm32 = B8 xx xx xx xx; ret = C3 (6 bytes total)
        // For 0: xor eax,eax = 31 C0; ret = C3 (3 bytes)

        var count = 0;
        for (var sym of symbols) {
            if (count >= MAX_PATCHES) {
                Logger.info("  ... (limited to " + MAX_PATCHES + ")");
                break;
            }
            try {
                var funcAddr = sym.addr;

                // Write patch bytes directly to function
                // mov eax, VALUE (B8 + 4 bytes little-endian) then ret (C3)
                if (retVal === 0) {
                    // xor eax, eax; ret = 31 C0 C3
                    MemoryUtils.writeMemory(funcAddr, [0x31, 0xC0, 0xC3]);
                } else if (retVal === 1) {
                    // mov eax, 1; ret = B8 01 00 00 00 C3
                    MemoryUtils.writeMemory(funcAddr, [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
                } else if (typeof retVal === "bigint") {
                    // mov rax, IMM64; ret = 48 B8 ... C3
                    var bytes = [0x48, 0xB8];
                    for (var i = 0n; i < 64n; i += 8n) {
                        bytes.push(Number((retVal >> i) & 0xFFn));
                    }
                    bytes.push(0xC3);
                    MemoryUtils.writeMemory(funcAddr, bytes);
                } else {
                    // mov eax, VALUE; ret
                    // Use unsigned right shift (>>>) to handle large positive values correctly
                    var b0 = retVal & 0xFF;
                    var b1 = (retVal >>> 8) & 0xFF;
                    var b2 = (retVal >>> 16) & 0xFF;
                    var b3 = (retVal >>> 24) & 0xFF;
                    MemoryUtils.writeMemory(funcAddr, [0xB8, b0, b1, b2, b3, 0xC3]);
                }

                Logger.info("  [PATCHED] " + sym.name + " @ 0x" + funcAddr);
                count++;
            } catch (e) {
                Logger.error("  [FAILED] " + sym.name + " @ 0x" + sym.addr + ": " + e.message);
            }
        }

        Logger.empty();
        Logger.info("  " + count + " function(s) patched -> return " + retVal);
        Logger.info("  NOTE: Patches are direct code modifications (not breakpoints)");
        Logger.info("  TIP: V8 caches results - navigate to a new page to see effect in JS");
        Logger.empty();

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
                        var callerMatch = callerLine.toString().match(/^([0-9a-fA-F`]+)\s+(.+)/);
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
                Logger.info("  Found " + callers.length + " potential caller(s) that may inline this function.");
                Logger.info("  If patch doesn't work, try: !patch(\"<caller_name>\",\"" + retVal + "\")");
                for (var c = 0; c < Math.min(callers.length, MAX_CALLER_DISPLAY); c++) {
                    Logger.info("    - " + callers[c].name);
                }
                Logger.empty();
            }
        }

    } catch (e) {
        Logger.error("Error: " + e.message);
    }

    return "";
}

/// Helper: Ensure the exit process handler is registered
function _ensureExitHandler() {
    if (g_exitHandlerRegistered) return;

    // Register a silent handler for Process Exit (epr)
    // We use ; g at the end to auto-continue unless we want to stop (we don't)
    var cmd = "sxe -c \"!on_process_exit; g\" epr";
    try {
        var ctl = SymbolUtils.getControl();
        ctl.ExecuteCommand(cmd);
        g_exitHandlerRegistered = true;
        Logger.info("  [Setup] Registered process exit handler for cleanup.");
    } catch (e) {
        Logger.warn("  [Setup] Failed to register process exit handler.");
    }
}

/// Helper: Handler for process exit (runs on every process exit)
function on_process_exit() {
    // This runs frequently, so keep it lightweight and silent unless action is taken
    try {
        if (g_spoofMap.size === 0) return;

        // Get current PID
        var currentPid = host.currentProcess.Id;

        // Check if this PID is in our spoof map
        var idsToRemove = [];
        for (var entry of g_spoofMap) {
            var clientId = entry[0];
            var activeSpoof = entry[1];
            if (activeSpoof.pid === currentPid) {
                idsToRemove.push(clientId);
            }
        }

        // Cleanup
        for (var id of idsToRemove) {
            var spoof = g_spoofMap.get(id);
            g_spoofMap.delete(id);
            Logger.info("\n  [Cleanup] Spoof state cleaned up for PID " + currentPid + " (Url: " + spoof.currentUrl + ")");
        }

        // Cache Cleanup: Remove broken/stale cache entries for this PID to prevent PID reuse issues
        GlobalCache.clearPid(currentPid);

    } catch (e) {
        // Suppress errors in exit handler to avoid spam
    }
}

/// Usage: !spoof_origin "https://target.com"
/// Spoofs the current origin to a target origin
/// Patches both host and full URL occurrences in memory
function spoof_origin(targetUrl) {
    Logger.section("Spoof Origin");

    var ctl = SymbolUtils.getControl();

    if (isEmpty(targetUrl)) {
        Logger.info("  Usage: !spoof_origin(\"https://target.com\")");
        Logger.empty();
        Logger.info("  Examples:");
        Logger.info("    !spoof_origin(\"https://google.com\")");
        Logger.info("    !spoof_origin(\"chrome://settings\")");
        Logger.info("    !spoof_origin(\"file://localhost\")");
        Logger.empty();
        Logger.info("  Patches all occurrences of current origin in memory.");
        Logger.empty();
        return "";
    }

    // Strip quotes from target and normalize (remove trailing slash)
    var targetOrigin = targetUrl.replace(/"/g, "").replace(/\/+$/, "");

    // Parse target into scheme and host
    var targetMatch = targetOrigin.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(.+)$/);
    if (!targetMatch) {
        Logger.warn("Invalid URL format. Use scheme://host (e.g., https://example.com)");
        return "";
    }
    var targetScheme = targetMatch[1];
    var targetHost = targetMatch[2];

    // Get current origin from renderer_site (this is the TRUE browser-side origin)
    Logger.info("  Target: " + targetOrigin);
    Logger.info("  Detecting true origin...");

    var trueOrigin = "";
    var clientId = null;
    try {
        // We need to parse client ID to look up in spoof map
        var cmdLine = getCommandLine();
        var clientMatch = cmdLine ? cmdLine.match(/--renderer-client-id=(\d+)/) : null;
        if (clientMatch) clientId = clientMatch[1];

        var site = renderer_site();
        if (site && site !== "" && site !== "(unknown)") {
            trueOrigin = site.replace(/\/+$/, "");
        }
    } catch (e) { }

    if (!trueOrigin) {
        Logger.empty();
        Logger.warn("Could not detect current origin.");
        Logger.info("Make sure you're in a renderer with a loaded page.");
        Logger.empty();
        return "";
    }

    // Determine what is currently in memory (Source)
    var currentOrigin = trueOrigin;
    if (clientId && g_spoofMap.has(clientId)) {
        currentOrigin = g_spoofMap.get(clientId).currentUrl;
        Logger.info("  [State] Detected active spoof: " + currentOrigin);
    } else {
        Logger.info("  [State] No active spoof detected. Using true origin.");
    }

    // Parse current into scheme and host
    var currentMatch = currentOrigin.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(.+)$/);
    if (!currentMatch) {
        Logger.warn("Could not parse source origin: " + currentOrigin);
        return "";
    }
    var currentScheme = currentMatch[1];
    var currentHost = currentMatch[2];

    if (currentOrigin === targetOrigin) {
        Logger.info("  Target matches current detected origin. No changes needed.");
        return "";
    }

    Logger.info("  Source: " + currentOrigin);
    Logger.info("  Current Host: " + currentHost + " -> Target Host: " + targetHost);
    Logger.empty();

    var totalPatched = 0;

    // Patch protocol/scheme (SecurityOrigin's protocol_ field)
    if (currentScheme !== targetScheme) {
        totalPatched += _patchStringInMemory(ctl, currentScheme, targetScheme, "Scheme (ASCII)", false);
    } else {
        Logger.info("  Schemes are identical (" + currentScheme + "), skipping");
    }

    // Patch host (SecurityOrigin's host_ field)
    if (currentHost !== targetHost) {
        totalPatched += _patchStringInMemory(ctl, currentHost, targetHost, "Host (ASCII)", false);
    } else {
        Logger.info("  Hosts are identical (" + currentHost + "), skipping");
    }

    Logger.empty();
    Logger.info("  Total: Patched " + totalPatched + " locations");
    Logger.empty();

    // Update State
    if (clientId) {
        if (targetOrigin === trueOrigin) {
            Logger.info("  Reverted to true origin. Clearing spoof state.");
            g_spoofMap.delete(clientId);
        } else {
            // New spoof - store state WITH PID
            var currentPid = host.currentProcess.Id;
            g_spoofMap.set(clientId, { currentUrl: targetOrigin, pid: currentPid });
            _ensureExitHandler();

        }
    } else {
        Logger.warn("  Could not determine Client ID. State not updated.");
    }

    return "";
}



/// =============================================================================
/// SANDBOX INSPECTION
/// =============================================================================

/// Check sandbox state
function sandbox_state() {
    Logger.section("Sandbox State");

    var processType = chrome_process_type();

    if (processType === "browser") {
        Logger.info("  Browser process - not sandboxed");
        Logger.empty();
        return "browser (not sandboxed)";
    }

    // Try to find sandbox state symbols
    Logger.info("  Checking sandbox state...");
    Logger.empty();

    try {
        var ctl = SymbolUtils.getControl();

        // Try to examine process token
        Logger.info("  Token Information:");
        Logger.info("  " + "-".repeat(40));

        // Get token integrity level using !token
        var tokenOutput = ctl.ExecuteCommand("!token -n");
        for (var line of tokenOutput) {
            if (line.indexOf("Impersonation") !== -1 ||
                line.indexOf("Integrity") !== -1 ||
                line.indexOf("Restricted") !== -1) {
                Logger.info("    " + line);
            }
        }
    } catch (e) {
        Logger.warn("Unable to query token (symbols may be needed)");
    }

    Logger.empty();

    // Check for sandbox::TargetServicesBase if symbols are available
    Logger.info("  Sandbox Breakpoints (for detailed analysis):");
    Logger.info("  " + "-".repeat(40));
    Logger.info("    bp sandbox!TargetServicesBase::Init");
    Logger.info("    bp sandbox!TargetServicesBase::LowerToken");
    Logger.empty();

    return "";
}

/// Analyze process token
function sandbox_token() {
    Logger.section("Process Token Analysis");

    try {
        var ctl = SymbolUtils.getControl();

        // Get detailed token info
        Logger.info("  Running !token...");
        Logger.empty();
        var tokenOutput = ctl.ExecuteCommand("!token");
        for (var line of tokenOutput) {
            Logger.info("  " + line);
        }
    } catch (e) {
        Logger.error("Error: " + e.message);
        Logger.info("Try: .reload /f ntdll.dll");
    }

    Logger.empty();
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
            "chrome!content::RenderProcessHostImpl::Init",
            "chrome!content::RenderProcessHostImpl::OnProcessLaunched",
            "chrome!content::ChildProcessLauncher::Launch"
        ],
        "Breaking when renderer processes start"
    );
}

/// Set breakpoint on sandbox token lowering
function bp_sandbox_lower() {
    return set_breakpoints(
        "Sandbox Token Breakpoints",
        [
            "chrome!sandbox::TargetServicesBase::LowerToken",
            "chrome!sandbox::ProcessState::SetRevertedToSelf"
        ],
        "Breaking when sandbox restricts token"
    );
}

/// Set breakpoint on Mojo interface binding
function bp_mojo_interface() {
    return set_breakpoints(
        "Mojo Interface Breakpoints",
        [
            "chrome!content::BrowserInterfaceBrokerImpl::GetInterface",
            "chrome!content::RenderProcessHostImpl::BindReceiver",
            "chrome!mojo::core::MessagePipeDispatcher::WriteMessage"
        ],
        "Tracking Mojo IPC"
    );
}

/// Set breakpoint on IPC message dispatch
function bp_ipc_message() {
    return set_breakpoints(
        "IPC Message Breakpoints",
        [
            "chrome!content::ChildProcessHost::OnMessageReceived",
            "chrome!IPC::ChannelMojo::OnMessageReceived"
        ],
        "IPC message logging"
    );
}



/// =============================================================================
/// PROCESS-SPECIFIC EXECUTION
/// =============================================================================

/// Get the process type of the current process
function getProcessType() {
    // Reuse safe helper logic without context switch (we are in current context)
    try {
        // Reuse logic of chrome_process_type
        var cmdLine = getCommandLine();
        if (isEmpty(cmdLine)) {
            return "renderer"; // Heuristic
        }
        var info = ProcessUtils.parseInfo(cmdLine);
        return info.type;
    } catch (e) {
        return "renderer";
    }
}

/// Check if current process matches a type
function isProcessType(targetType) {
    return getProcessType() === targetType;
}




/// Check sandbox status for ALL processes
function sandbox_status_all() {
    Logger.section("Sandbox Status Dashboard");
    Logger.info("  ID    PID       Type              Integrity Level           Status");
    Logger.info("  " + "-".repeat(90));

    var ctl = SymbolUtils.getControl();

    // Use our trusted helpers
    var processList = ProcessUtils.getList();

    // Remember original context
    var originalId = ProcessUtils.getCurrentSysId();

    for (var proc of processList) {
        try {
            var sysId = proc.sysId;
            if (sysId === "?" || sysId === null) continue;

            var type = proc.type;
            var pid = proc.pid;

            var status = "Unknown";

            // Switch and query token safely
            var integrity = ProcessUtils.withContext(sysId, function () {
                var result = "Unknown";
                try {
                    var output = SymbolUtils.execute("!token");
                    for (var line of output) {
                        // Match "Integrity Level" or "IntegrityLevel" followed by colon
                        if (/Integrity.*Level.*:/i.test(line)) {
                            var parts = line.split(":");
                            if (parts.length > 1) result = parts[1].trim();
                            break;
                        }
                    }
                } catch (e) { result = "Error reading token"; }
                return result;
            });

            // Map SIDs to Names using lookup table
            var sids = Object.keys(INTEGRITY_LEVELS);
            for (var i = 0; i < sids.length; i++) {
                var sid = sids[i];
                if (integrity.indexOf(sid) !== -1) {
                    integrity = INTEGRITY_LEVELS[sid] + " (" + sid + ")";
                    break;
                }
            }

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
            if (integrity.length > MAX_INTEGRITY_DISPLAY_LENGTH) integrity = integrity.substring(0, MAX_INTEGRITY_DISPLAY_LENGTH - 3) + "...";

            Logger.info(
                "  " + sysId.toString().padEnd(6) +
                pid.toString().padEnd(10) +
                type.padEnd(18) +
                integrity.padEnd(26) +
                status
            );

        } catch (e) {
            Logger.error("Error processing PID " + pid);
        }
    }

    Logger.empty();
    return "";
}



/// =============================================================================
/// SITE ISOLATION
/// =============================================================================

/// Check Site Isolation status
function site_isolation_status() {
    Logger.section("Site Isolation Status");

    var cmdLine = getCommandLine();

    // Check command line flags
    var flags = {
        "site-per-process": cmdLine.indexOf("--site-per-process") !== -1,
        "disable-site-isolation": cmdLine.indexOf("--disable-site-isolation") !== -1,
        "isolate-origins": cmdLine.indexOf("--isolate-origins") !== -1
    };

    Logger.info("  Command Line Flags:");
    Logger.info("  " + "-".repeat(40));
    Logger.info("    --site-per-process:          " + (flags["site-per-process"] ? "ENABLED" : "not set"));
    Logger.info("    --disable-site-isolation:    " + (flags["disable-site-isolation"] ? "WARNING: DISABLED" : "not set"));
    Logger.info("    --isolate-origins:           " + (flags["isolate-origins"] ? "ENABLED" : "not set"));

    // Extract isolated origins if present
    if (flags["isolate-origins"]) {
        var match = cmdLine.match(/--isolate-origins=([^\s"]+)/);
        if (match) {
            Logger.info("");
            Logger.info("  Isolated Origins: " + match[1]);
        }
    }

    Logger.info("");
    Logger.info("  Runtime Check Breakpoints:");
    Logger.info("  " + "-".repeat(40));
    Logger.info("    bp chrome!content::SiteIsolationPolicy::UseDedicatedProcessesForAllSites");
    Logger.info("    bp chrome!content::SiteInstanceImpl::GetSiteForURL");
    Logger.empty();

    return "";
}

/// Helper: Check if chrome.dll module is loaded in current process
function _hasChromeModule() {
    try {
        var modules = host.currentProcess.Modules;
        for (var mod of modules) {
            var modName = mod.Name.toLowerCase();
            if (modName === "chrome.dll" || modName.endsWith("\\chrome.dll")) {
                Logger.info("    Found module: " + mod.Name);
                return true;
            }
        }
    } catch (modErr) {
        Logger.warn("    Warning: Could not enumerate modules");
    }
    return false;
}

/// Helper: Find g_frame_map LazyInstance address
function _findFrameMapAddress(ctl) {
    try {
        var xOutput = ctl.ExecuteCommand("x chrome!*g_frame_map*");
        for (var line of xOutput) {
            var lineStr = line.toString();
            Logger.info("    > " + lineStr);
            var addr = SymbolUtils.extractAddress(line);
            if (addr) return addr;
        }
    } catch (xErr) {
        Logger.error("Symbol lookup failed: " + (xErr.message || xErr));
        Logger.info("Try: .reload /f chrome.dll");
    }
    return null;
}

/// Helper: Read FrameMap pointer from LazyInstance
function _readFrameMapPointer(lazyInstanceAddr) {
    try {
        var lazyAddrVal = BigInt("0x" + lazyInstanceAddr);
        var ptrValue = host.memory.readMemoryValues(host.parseInt64(lazyAddrVal.toString(16), 16), 1, 8)[0];
        var mapAddr = ptrValue.toString(16);
        if (isValidPointer(mapAddr)) {
            return mapAddr;
        }
    } catch (e) { }
    return null;
}

/// Helper: Parse frame entries from dx output
function _parseFrameMapEntries(ctl, mapAddr) {
    var frames = [];
    var currentWebFrame = null;
    var dxCmd = "dx -r5 *((content::`anonymous namespace'::FrameMap*)0x" + mapAddr + ")";
    var mapOutput = ctl.ExecuteCommand(dxCmd);

    for (var line of mapOutput) {
        var lineStr = line.toString();
        var firstMatch = lineStr.match(/first\s*:\s*(0x[0-9a-fA-F`]+)\s*\[Type:\s*blink::WebFrame/i);
        if (firstMatch) {
            currentWebFrame = firstMatch[1].replace(/`/g, "");
        }
        var secondMatch = lineStr.match(/second\s*:\s*(0x[0-9a-fA-F`]+)\s*\[Type:\s*content::RenderFrameImpl/i);
        if (secondMatch && currentWebFrame) {
            frames.push({
                webFrame: currentWebFrame,
                renderFrame: secondMatch[1].replace(/`/g, "")
            });
            currentWebFrame = null;
        }
    }
    return frames;
}

/// Helper: Extract URL from a frame using various methods
function _extractFrameUrl(ctl, f) {
    var webFrameHex = normalizeAddress(f.webFrame);
    if (!webFrameHex) return "";
    var localFrameAddr = null;
    var frameCompressed = getCompressedMember(webFrameHex, "(blink::WebLocalFrameImpl*)", "frame_");
    if (frameCompressed !== null) {
        localFrameAddr = MemoryUtils.decompressCppgcPtr(frameCompressed, f.webFrame);
    }

    if (!localFrameAddr) return "";

    // Try via FrameLoader -> DocumentLoader
    var loaderCompressed = getCompressedMember(normalizeAddress(localFrameAddr), "(blink::LocalFrame*)", "loader_");
    if (loaderCompressed !== null) {
        var loaderAddr = MemoryUtils.decompressCppgcPtr(loaderCompressed, localFrameAddr);
        if (isValidPointer(loaderAddr)) {
            var docLoaderCompressed = getCompressedMember(normalizeAddress(loaderAddr), "(blink::FrameLoader*)", "document_loader_");
            if (docLoaderCompressed !== null) {
                var docLoaderAddr = MemoryUtils.decompressCppgcPtr(docLoaderCompressed, loaderAddr);
                if (isValidPointer(docLoaderAddr)) {
                    var url = readUrlStringFromDx(docLoaderAddr.toString(16), "(blink::DocumentLoader*)");
                    if (url) return url;
                }
            }
        }
    }

    // Fallback: Try via dom_window_ -> document_ -> url_
    var windowCompressed = getCompressedMember(normalizeAddress(localFrameAddr), "(blink::LocalFrame*)", "dom_window_");
    if (windowCompressed !== null) {
        var windowAddr = MemoryUtils.decompressCppgcPtr(windowCompressed, localFrameAddr);
        if (isValidPointer(windowAddr)) {
            var docCompressed = getCompressedMember(normalizeAddress(windowAddr), "(blink::LocalDOMWindow*)", "document_");
            if (docCompressed !== null) {
                var docAddr = MemoryUtils.decompressCppgcPtr(docCompressed, windowAddr);
                if (isValidPointer(docAddr)) {
                    return readUrlStringFromDx(docAddr, "(blink::Document*)") || "";
                }
            }
        }
    }
    return "";
}

/// Helper: Get process_label_id_ from RenderFrameImpl
function _getFrameLabelId(ctl, renderFrame) {
    try {
        var rfCmd = "dx -r0 ((content::RenderFrameImpl*)" + renderFrame + ")->process_label_id_";
        var rfOutput = ctl.ExecuteCommand(rfCmd);
        for (var rfLine of rfOutput) {
            if (rfLine.toString().indexOf("process_label_id_") !== -1) {
                var idMatch = rfLine.toString().match(/:\s*(\d+)/);
                if (idMatch) return idMatch[1];
            }
        }
    } catch (e) { }
    return "N/A";
}

/// Helper: Display single frame info
function _displayFrameInfo(ctl, f, index) {
    var rfId = _getFrameLabelId(ctl, f.renderFrame);
    Logger.info("  [Index: " + index + "] RenderFrameImpl:  " + f.renderFrame);
    Logger.info("       WebFrame:         " + f.webFrame);

    // Get LocalFrame address (what frame commands work with)
    var localFrame = BlinkUnwrap.getLocalFrame(f.webFrame);
    if (localFrame && localFrame !== "0") {
        Logger.info("       LocalFrame:       0x" + localFrame);
    }

    var urlStr = _extractFrameUrl(ctl, f);
    if (urlStr) {
        Logger.info("       URL:              " + urlStr);
    } else {
        Logger.info("       URL:              (use dx to inspect)");
    }
    Logger.empty();
}

/// List all frames in the current renderer process
function renderer_frames() {
    Logger.section("Renderer Frames");

    var ctl;
    try {
        ctl = SymbolUtils.getControl();
    } catch (e) {
        Logger.error("Cannot get debugger control interface.");
        return "";
    }

    // Verify we're in a renderer
    try {
        var cmdLine = getCommandLine();
        if (cmdLine) {
            var info = ProcessUtils.parseInfo(cmdLine);
            if (info && info.type !== "renderer") {
                Logger.warn("May not be a renderer (detected: " + info.type + ")");
                Logger.info("  Continuing anyway...");
                Logger.empty();
            }
        }
    } catch (e) {
        Logger.warn("Could not verify process type (continuing anyway)");
        Logger.empty();
    }

    try {
        Logger.info("  Step 1: Looking for g_frame_map symbol...");

        if (!_hasChromeModule()) {
            Logger.info("  chrome.dll not found in this process.");
            Logger.info("  This command only works in renderer processes.");
            Logger.info("  Use !procs to list processes and |<id>s to switch.");
            Logger.empty();
            return "";
        }

        var lazyInstanceAddr = _findFrameMapAddress(ctl);
        if (!lazyInstanceAddr) {
            Logger.warn("Could not find g_frame_map symbol.");
            Logger.info("Make sure symbols are loaded (try: .reload /f chrome.dll)");
            Logger.empty();
            return "";
        }

        Logger.info("  g_frame_map (LazyInstance) at: 0x" + lazyInstanceAddr);
        Logger.info("  Step 2: Reading private_instance_ pointer...");

        var mapAddr = _readFrameMapPointer(lazyInstanceAddr);
        if (!mapAddr) {
            Logger.info("  LazyInstance not yet initialized (no frames created yet).");
            Logger.empty();
            return "";
        }

        Logger.info("  FrameMap (actual map) at: 0x" + mapAddr);
        Logger.empty();
        Logger.info("  Enumerating frames...");
        Logger.info("  " + "-".repeat(70));
        Logger.empty();

        var frames = _parseFrameMapEntries(ctl, mapAddr);

        if (frames.length > 0) {
            Logger.info("  Found " + frames.length + " frame(s):");
            Logger.empty();

            var oilpanBase = MemoryUtils.getCppgcCageBase();
            if (oilpanBase) {
                Logger.info("  (Oilpan Cage Base: 0x" + oilpanBase + ")");
                Logger.empty();
            }

            for (var i = 0; i < frames.length; i++) {
                _displayFrameInfo(ctl, frames[i], i);
            }
        } else {
            Logger.info("  No frames found. Map may be empty.");
            Logger.empty();
            Logger.info("  Manual inspection commands:");
            Logger.info("    dq 0x" + mapAddr + " L10");
            Logger.info("    dx *((content::`anonymous namespace'::FrameMap*)0x" + mapAddr + ")");
            Logger.empty();
        }

        Logger.empty();
        Logger.info("  Useful commands:");
        Logger.info("    dx ((content::RenderFrameImpl*)<addr>)         - Inspect RenderFrameImpl");
        Logger.info("    dx ((content::RenderFrameImpl*)<addr>)->frame_ - Get WebLocalFrame");
        Logger.info("    dx ((blink::WebLocalFrame*)<addr>)             - Inspect WebFrame");
        Logger.empty();

    } catch (e) {
        Logger.error("Error: " + (e.message || e.toString()));
        if (e.stack) {
            Logger.info("  Stack: " + e.stack);
        }
        Logger.empty();
        Logger.info("  Manual approach:");
        Logger.info("    x chrome!*g_frame_map*");
        Logger.info("    dq <addr> L1                ; Read LazyInstance.private_instance_");
        Logger.info("    dx *((content::`anonymous namespace'::FrameMap*)<ptr>)");
        Logger.empty();
    }

    return "";
}



/// Helper: Show usage for run_in_* commands and execute if command provided
function _runInProcessType(command, processType, exampleCmd) {
    if (isEmpty(command)) {
        var displayName = processType.charAt(0).toUpperCase() + processType.slice(1);
        Logger.section("Run in " + displayName);
        Logger.info("  Usage: !run_in_" + processType + " \"<windbg command>\"");
        Logger.info("  Example: !run_in_" + processType + " \"" + exampleCmd + "\"");
        Logger.empty();
        Logger.info("  Works from ANY process - automatically finds and runs in " + processType + ".");
        Logger.empty();
        return "";
    }
    return ProcessUtils.runInType(processType, command);
}


/// Execute a command only in renderer processes (works from any process context)
function run_in_renderer(command) {
    return _runInProcessType(command, "renderer", "bp chrome!v8::internal::Heap::CollectGarbage");
}

/// Execute a command only in browser process (works from any process context)
function run_in_browser(command) {
    return _runInProcessType(command, "browser", "bp chrome!Browser::Create");
}

/// Execute a command only in GPU process (works from any process context)
function run_in_gpu(command) {
    return _runInProcessType(command, "gpu-process", "bp chrome!gpu::CommandBufferService::Flush");
}



/// Set up commands to run automatically when a renderer process attaches
function on_renderer_attach(command) {
    Logger.section("Renderer Auto-Attach Setup");

    if (isEmpty(command)) {
        Logger.info("  This sets up commands to run when new renderer processes attach.");
        Logger.empty();
        Logger.info("  Usage: !on_renderer_attach \"<windbg command>\"");
        Logger.empty();
        Logger.info("  Examples:");
        Logger.info("    !on_renderer_attach \"!sandbox_state\"");
        Logger.info("    !on_renderer_attach \"bp chrome!blink::Document::CreateRawElement\"");
        Logger.info("    !on_renderer_attach \".echo Renderer attached!\"");
        Logger.empty();
        Logger.header("Registered commands:");
        for (var i = 0; i < g_rendererAttachCommands.length; i++) {
            Logger.info("    " + (i + 1) + ": " + g_rendererAttachCommands[i]);
        }
        if (g_rendererAttachCommands.length === 0) {
            Logger.info("    (none)");
        }
        Logger.empty();
        Logger.info("  TIP: To trigger on child process creation, use WinDbg:");
        Logger.info("    sxe -c \"!run_in_renderer \\\"<cmd>\\\"\" cpr");
        Logger.empty();
        return "";
    }

    g_rendererAttachCommands.push(command);
    Logger.info("  Added: " + command);
    Logger.info("  Total registered commands: " + g_rendererAttachCommands.length);
    Logger.empty();

    // Use helper to register sxe handler
    _registerRendererSxeHandler("!run_in_renderer \"" + command + "\"", "Command");

    return "";
}

/// Execute a script file only in renderer processes (works from any process context)
function run_script_in_renderer(scriptPath) {
    if (isEmpty(scriptPath)) {
        Logger.section("Run Script in Renderer");
        Logger.info("  Usage: !run_script_in_renderer \"<path to .js script>\"");
        Logger.empty();
        Logger.info("  Examples:");
        Logger.info("    !run_script_in_renderer \"C:\\scripts\\renderer_hooks.js\"");
        Logger.info("    !run_script_in_renderer \"renderer_security.js\"");
        Logger.empty();
        Logger.info("  Works from ANY process - automatically loads in all renderers.");
        Logger.empty();
        return "";
    }

    // Reuse run_in_renderer to handle process iteration
    var loadCmd = ".scriptload " + scriptPath;
    return run_in_renderer(loadCmd);
}

/// Set up a script to load automatically when renderer processes attach
function script_in_renderer_attach(scriptPath) {
    Logger.section("Script Auto-Load on Renderer Attach");

    if (isEmpty(scriptPath)) {
        Logger.info("  Usage: !script_in_renderer_attach \"<path to .js script>\"");
        Logger.empty();
        Logger.info("  This will auto-load the script when new renderer processes spawn.");
        Logger.empty();
        Logger.info("  Examples:");
        Logger.info("    !script_in_renderer_attach \"renderer_hooks.js\"");
        Logger.info("    !script_in_renderer_attach \"C:\\research\\exploit_test.js\"");
        Logger.empty();
        return "";
    }

    Logger.info("  Registering: " + scriptPath);
    Logger.empty();

    // Use helper to register sxe handler
    var escapedPath = scriptPath.replace(/\\/g, "\\\\");
    _registerRendererSxeHandler("!run_script_in_renderer \"" + escapedPath + "\"", "Script");

    return "";
}

/// =============================================================================
/// SECURITY RESEARCH BREAKPOINTS
/// =============================================================================

/// Break on mojo::ReportBadMessage - catches security boundary violations
function bp_bad_message() {
    return set_breakpoints(
        "Bad Message Breakpoints (Security Violations)",
        [
            "chrome!mojo::ReportBadMessage"
        ],
        "Breaking on security violations (check message string)"
    );
}

/// Break on security policy checks
function bp_security_check() {
    return set_breakpoints(
        "Security Policy Breakpoints",
        [
            { sym: "chrome!content::ChildProcessSecurityPolicyImpl::CanAccessDataForOrigin", desc: "Origin access check" },
            { sym: "chrome!content::ChildProcessSecurityPolicyImpl::CanCommitURL", desc: "URL commit check" },
            { sym: "chrome!content::ChildProcessSecurityPolicyImpl::GetProcessLock", desc: "Process lock query" },
            { sym: "chrome!content::SiteIsolationPolicy::UseDedicatedProcessesForAllSites", desc: "Site isolation check" },
            { sym: "chrome!content::SiteInstanceImpl::GetProcess", desc: "SiteInstance process" },
            { sym: "chrome!sandbox::TargetServicesBase::LowerToken", desc: "Sandbox token lowering" }
        ],
        "Breaking on security policy checks"
    );
}

/// Enable IPC/Mojo message tracing
function trace_ipc() {
    return set_breakpoints(
        "IPC Tracing Mode",
        [
            { sym: "chrome!mojo::MessageDispatcher::Accept", desc: "Mojo message accept", cmd: 'bp chrome!mojo::MessageDispatcher::Accept ".echo [IPC] Mojo message accept; k 3; g"' },
            { sym: "chrome!content::BrowserInterfaceBrokerImpl::GetInterface", desc: "Interface broker", cmd: 'bp chrome!content::BrowserInterfaceBrokerImpl::GetInterface ".echo [IPC] Interface broker; k 3; g"' },
            { sym: "chrome!IPC::ChannelMojo::OnMessageReceived", desc: "Legacy IPC receive", cmd: 'bp chrome!IPC::ChannelMojo::OnMessageReceived ".echo [IPC] Legacy IPC receive; k 3; g"' }
        ],
        "Logging IPC traffic (noisy!)"
    );
}

/// =============================================================================
/// VULNERABILITY HUNTING
/// =============================================================================

/// Set breakpoints for common vulnerability patterns
function vuln_hunt() {
    Logger.section("Vulnerability Hunting Mode");
    Logger.info("  Setting breakpoints for common vulnerability patterns.");
    Logger.empty();

    try {
        var ctl = SymbolUtils.getControl();

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
            Logger.info("  " + cat.name + ":");
            Logger.info("  " + "-".repeat(50));

            for (var i = 0; i < cat.targets.length; i++) {
                var target = cat.targets[i];
                Logger.info("    [" + target.desc + "]");
                Logger.info("      bp " + target.sym);
                try {
                    ctl.ExecuteCommand("bp " + target.sym);
                } catch (e) { }
            }
            Logger.empty();
        }

        Logger.info("  Breakpoints set. Use 'bl' to list, 'bc *' to clear.");
        Logger.empty();

    } catch (e) {
        Logger.error("Error: " + e.message);
    }

    return "";
}

/// Display heap/allocator information
function heap_info() {
    Logger.section("Heap / PartitionAlloc Info");

    try {
        var ctl = SymbolUtils.getControl();
        var procType = getProcessType();

        Logger.info("  Process Type: " + procType);
        Logger.empty();

        Logger.info("  PartitionAlloc Structures:");
        Logger.info("  " + "-".repeat(50));
        Logger.info("    dt chrome!base::PartitionRoot");
        Logger.info("    dt chrome!base::internal::SlotSpanMetadata");
        Logger.empty();

        Logger.info("  Useful Commands:");
        Logger.info("  " + "-".repeat(50));
        Logger.info("    !heap -s                           - NT heap summary");
        Logger.info("    !heap -a <addr>                    - Analyze heap address");
        Logger.info("    dps <addr> L10                     - Dump pointers at address");
        Logger.info("    !address <addr>                    - Memory region info");
        Logger.empty();

        Logger.info("  PartitionAlloc Breakpoints:");
        Logger.info("  " + "-".repeat(50));

        var paTargets = [
            "base::PartitionRoot::Alloc",
            "base::PartitionRoot::Free",
            "base::internal::PartitionBucket::SlowPathAlloc"
        ];

        for (var i = 0; i < paTargets.length; i++) {
            var sym = "chrome!" + paTargets[i];
            Logger.info("    bp " + sym);
        }

        Logger.empty();
        Logger.info("  V8 Heap (renderer only):");
        Logger.info("  " + "-".repeat(50));
        Logger.info("    dt chrome!v8::internal::Heap");
        Logger.info("    bp chrome!v8::internal::Heap::CollectGarbage");
        Logger.empty();

    } catch (e) {
        Logger.error("Error: " + e.message);
    }

    return "";
}

/// =============================================================================
/// BLINK HOOKS
/// =============================================================================

function blink_help() {
    Logger.section("Blink DOM Security Hooks");
    Logger.info("  !bp_element   - Break on DOM element creation");
    Logger.info("  !bp_nav       - Break on navigation/location changes");
    Logger.info("  !bp_pm        - Break on postMessage (cross-origin comms)");
    Logger.info("  !bp_fetch     - Break on fetch/XHR requests");
    Logger.empty();
    Logger.info("  Target symbols (chrome.dll):");
    Logger.info("    blink::Document::CreateRawElement");
    Logger.info("    blink::LocalDOMWindow::DispatchPostMessage");
    Logger.info("    blink::FetchManager::Fetch");
    Logger.empty();
    return "";
}

function bp_element() {
    return _bpFromConfig("element");
}

function bp_nav() {
    return _bpFromConfig("nav");
}

function bp_pm() {
    return _bpFromConfig("pm");
}

function bp_fetch() {
    return _bpFromConfig("fetch");
}

/// =============================================================================
/// V8 HOOKS
/// =============================================================================

function v8_help() {
    Logger.section("V8 Exploitation Hooks");
    Logger.info("  !bp_compile   - Break on script compilation");
    Logger.info("  !bp_gc        - Break on garbage collection");
    Logger.info("  !bp_wasm      - Break on WebAssembly compilation");
    Logger.info("  !bp_jit       - Break on JIT code generation");
    Logger.empty();
    Logger.info("  Target module: chrome.dll (v8 is statically linked)");
    Logger.empty();
    Logger.info("  Tips:");
    Logger.info("  - V8 symbols are large, use: .symopt+0x10 for deferred loading");
    Logger.info("  - For heap inspection: dt chrome!v8::internal::Heap");
    Logger.empty();
    return "";
}

function bp_compile() {
    return _bpFromConfig("compile");
}

function bp_gc() {
    return _bpFromConfig("gc");
}

function bp_wasm() {
    return _bpFromConfig("wasm");
}

function bp_jit() {
    return _bpFromConfig("jit");
}

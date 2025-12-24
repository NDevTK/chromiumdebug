/// =============================================================================
/// Chromium Security Research WinDbg Script
/// =============================================================================
/// A comprehensive debugging toolkit for Chromium security research.
/// Load this script with: .scriptload chromium_security.js
/// =============================================================================

"use strict";

/// Global state
var g_rendererAttachCommands = [];

/// Constants
const MAX_PATCHES = 50;
const MAX_CALLER_DISPLAY = 3;
const BROWSER_CMDLINE_MIN_LENGTH = 500;
const USER_MODE_ADDR_LIMIT = "0x7fffffffffff";
const MIN_PTR_VALUE_LENGTH = 4;

/// Helper: Check if string is empty or null
function isEmpty(str) {
    return !str || str === "";
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
        try {
            var output = this.getControl().ExecuteCommand("x " + pattern);
            for (var line of output) {
                var addr = this.extractAddress(line);
                if (addr) return addr;
            }
        } catch (e) { }
        return null;
    }

    /// Execute command with fallback on error (DRY helper)
    static tryExecute(cmd, fallback = []) {
        try { return this.getControl().ExecuteCommand(cmd); } catch (e) { return fallback; }
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
        } catch (e) { }
        return null;
    }
}

class MemoryUtils {
    // Cache for cage bases
    static _v8CageBase = null;
    static _cppgcCageBase = null;

    /// Invalidate cached cage bases (call when switching processes)
    static invalidateCaches() {
        this._v8CageBase = null;
        this._cppgcCageBase = null;
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
        } catch (e) { }
        return null;
    }

    static parseBigInt(input) {
        if (typeof input === "string") {
            var ptrStr = input.replace(/`/g, "");
            return BigInt(ptrStr.startsWith("0x") ? ptrStr : "0x" + ptrStr);
        } else if (typeof input === "number") {
            return BigInt("0x" + input.toString(16));
        } else {
            return BigInt(input);
        }
    }

    static getV8CageBase() {
        if (this._v8CageBase !== null) return this._v8CageBase;
        this._v8CageBase = this.readGlobalPointer("chrome!v8::internal::MainCage::base_");
        return this._v8CageBase;
    }

    static getCppgcCageBase() {
        if (this._cppgcCageBase !== null) return this._cppgcCageBase;
        this._cppgcCageBase = this.readGlobalPointer("chrome!cppgc::internal::CageBaseGlobal::g_base_");
        return this._cppgcCageBase;
    }

    static decompressV8Ptr(compressedPtr) {
        var cageBase = this.getV8CageBase();
        if (!cageBase) return null;

        var base = BigInt("0x" + cageBase);
        var compressed = this.parseBigInt(compressedPtr);

        // Sign-extend 32-bit (V8 uses signed offsets)
        if (compressed > 0x7FFFFFFF) {
            compressed = compressed - BigInt("0x100000000");
        }

        var fullPtr = base + compressed;
        return fullPtr.toString(16);
    }

    static decompressCppgcPtr(compressedPtr, contextAddr) {
        const kPointerCompressionShift = 3n;
        const kCageBaseMask = BigInt("0xFFFFFFFC00000000"); // 16GB alignment?

        var compressed = this.parseBigInt(compressedPtr);
        if (compressed === 0n) return null;

        // Sign-extend if necessary (assuming 32-bit signed compressed value mostly positive)
        // If compressed is treated as unsigned 32-bit:
        if (compressed < 0n) compressed = compressed & 0xFFFFFFFFn;

        // Shift
        var offset = compressed << kPointerCompressionShift;

        // Combine with Cage Base
        if (contextAddr) {
            var context = BigInt(contextAddr.toString().startsWith("0x") ? contextAddr : "0x" + contextAddr);
            var base = context & kCageBaseMask;
            var fullPtr = base | offset;
            return fullPtr.toString(16);
        } else {
            // Fallback to global cage base if available
            var cage = this.getCppgcCageBase();
            if (cage) {
                var base = BigInt("0x" + cage);
                return (base | offset).toString(16);
            }
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

    /// Write string to memory (overwriting existing buffer)
    static writeStringImpl(implAddr, newString) {
        var ctl = SymbolUtils.getControl();
        var hexAddr = implAddr.toString().startsWith("0x") ? implAddr : "0x" + implAddr;

        var is8Bit = false;
        var currentLen = 0;
        var headerParsed = false;

        // Try raw memory read first (more reliable than dx symbols sometimes)
        // Layout assumption (x64):
        // +0: RefCount (4b)
        // +4: Length (4b)
        // +8: Hash/Flags (4b)
        try {
            var cmd = "dd " + hexAddr + " L4";
            var out = ctl.ExecuteCommand(cmd);
            for (var line of out) {
                // Logger.info("  [Debug] Raw Header: " + line); // Dump for analysis
                var parts = line.toString().trim().split(/\s+/);
                if (parts.length >= 4) {
                    // parts[0] is addr
                    // parts[1] (Offset 0), parts[2] (Offset 4), parts[3] (Offset 8)

                    var val1 = parseInt(parts[1], 16);
                    var val2 = parseInt(parts[2], 16);

                    // Heuristic: Length usually logical (e.g. < 1000). RefCount can be large/small.
                    // If dx failed, we rely on these.

                    // Assume +4 is length for now, but check if correct
                    var lenStr = parts[2];
                    if (lenStr) {
                        currentLen = parseInt(lenStr, 16);
                        headerParsed = true;
                    }
                }
                break;
            }
        } catch (e) { }

        // Fallback to dx if raw read failed or yielded 0 (and we suspect it's wrong)
        if (!headerParsed || currentLen === 0) {
            // ... existing dx logic ...
            // (Omitting here to keep it clean, but if raw failed, dx likely will too)
        }

        // Try dx for 8bit if raw didn't confirm
        try {
            var cmd = "dx ((WTF::StringImpl*)" + hexAddr + ")->is8Bit()";
            var out = ctl.ExecuteCommand(cmd);
            for (var line of out) {
                if (line.toString().includes("true")) is8Bit = true;
            }
        } catch (e) { }

        // Logger.info("  [Debug] StringImpl (Raw): Addr=" + hexAddr + " Len=" + currentLen + " 8Bit=" + is8Bit);

        if (currentLen === 0) {
            Logger.warn("  [Warning] Length detected as 0. This might be empty string OR read failure.");
            // If we write to 0 length, we corrupt memory if it's not actually 0.
            // If target string is empty, we shouldn't be here (attr loop check).
            // But let's allow writing if user forces? No, unsafe.
            if (newString.length > 0) {
                Logger.error("Cannot overwrite: Existing string length appears to be 0 or unreadable.");
                return;
            }
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
        } catch (e) { }

        // Fallback: Assume offset 12 (packed) or 16 (aligned)
        if (!dataAddr) {
            // StringImpl is explicitly aligned?
            // Usually sizeof(StringImpl) = 12 on 32-bit (?), 16 on 64-bit (due to alignment padding after offset 12?)
            // Let's assume +12 if header is 3x4 bytes.
            // But on x64, 16 is safer guess?
            var baseInt = BigInt(hexAddr);
            // Verify if data is at +16
            // We can check if existing chars match?
            // Too complex.
            // Let's default to +16 for x64.
            var offset = 16n; // 12 + 4 padding
            // Wait, flags is at +8. +12 might be data?
            // If is8Bit, it might be +12.
            // If 16Bit, it must be aligned?
            // Layout Analysis:
            // +0: RefCount
            // +4: Length
            // +8: Hash/Flags
            // +12: Data Start (packed)
            dataAddr = (baseInt + 12n).toString(16);
            Logger.warn("  [Warning] guessing data address at offset +0xC.");
        }

        // Write
        if (is8Bit) {
            var bytes = [];
            for (var i = 0; i < newString.length; i++) bytes.push(newString.charCodeAt(i));
            // Pad remainder with nulls
            while (bytes.length < currentLen) bytes.push(0);
            this.writeMemory(dataAddr, bytes);
        } else {
            // 16-bit write
            var bytes = [];
            for (var i = 0; i < newString.length; i++) {
                var c = newString.charCodeAt(i);
                bytes.push(c & 0xFF);
                bytes.push((c >> 8) & 0xFF);
            }
            // Pad remainder with nulls (2 bytes per char)
            while (bytes.length < currentLen * 2) bytes.push(0);
            this.writeMemory(dataAddr, bytes);
        }

        // Update length
        // ed expects hex by default (usually), or we explicitly use 0x prefix.
        // If length is 13, toString(16) is "d".
        var lenCmd = "ed " + hexAddr + "+4 0x" + newString.length.toString(16);
        ctl.ExecuteCommand(lenCmd);

        Logger.info("Overwrote string in memory at 0x" + dataAddr + ".");
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

    static getSwitch(cmdLine, name) {
        var match = cmdLine.match(new RegExp("--" + name + "(=([^\\s\"]+|\"[^\"]*\"))?"));
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
            try { ctl.ExecuteCommand(cmd); } catch (e) { }
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
            var m = l.match(/: (0x[0-9a-fA-F`]+)/);
            if (m) {
                var addr = m[1].replace(/`/g, "");
                var ptrVal = host.memory.readMemoryValues(host.parseInt64(addr, 16), 1, 4)[0];
                return ptrVal;
            }
        }
    } catch (e) { }
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
    } catch (e) { }
    return null;
}

/// =============================================================================
/// BLINK DOM UNWRAPPING UTILITIES
/// =============================================================================

/// BlinkUnwrap: Utility class for traversing Blink DOM objects using pointer decompression
class BlinkUnwrap {
    /// Get LocalFrame from WebLocalFrameImpl
    /// Path: WebLocalFrameImpl -> frame_ (compressed) -> LocalFrame
    static getLocalFrame(webFrameAddr) {
        var webFrameHex = webFrameAddr.toString().startsWith("0x") ? webFrameAddr : "0x" + webFrameAddr;
        var frameCompressed = getCompressedMember(webFrameHex, "(blink::WebLocalFrameImpl*)", "frame_");
        if (frameCompressed === null) return null;
        return MemoryUtils.decompressCppgcPtr(frameCompressed, webFrameAddr);
    }

    /// Get LocalDOMWindow from LocalFrame
    /// Path: LocalFrame -> dom_window_ (compressed) -> LocalDOMWindow
    static getDomWindow(localFrameAddr) {
        var frameHex = localFrameAddr.toString().startsWith("0x") ? localFrameAddr : "0x" + localFrameAddr;
        var windowCompressed = getCompressedMember(frameHex, "(blink::LocalFrame*)", "dom_window_");
        if (windowCompressed === null) return null;
        return MemoryUtils.decompressCppgcPtr(windowCompressed, localFrameAddr);
    }

    /// Get Document from LocalDOMWindow
    /// Path: LocalDOMWindow -> document_ (compressed) -> Document
    static getDocument(domWindowAddr) {
        var windowHex = domWindowAddr.toString().startsWith("0x") ? domWindowAddr : "0x" + domWindowAddr;
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
            var docHex = documentAddr.toString().startsWith("0x") ? documentAddr : "0x" + documentAddr;
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

    /// Get Document URL
    static getDocumentUrl(documentAddr) {
        var docHex = documentAddr.toString().replace(/^0x/, "");
        return readUrlStringFromDx(docHex, "(blink::Document*)");
    }

    /// Get first child of a node (ContainerNode::first_child_)
    static getFirstChild(nodeAddr) {
        var nodeHex = nodeAddr.toString().startsWith("0x") ? nodeAddr : "0x" + nodeAddr;
        var childCompressed = getCompressedMember(nodeHex, "(blink::ContainerNode*)", "first_child_");
        if (childCompressed === null) return null;
        return MemoryUtils.decompressCppgcPtr(childCompressed, nodeAddr);
    }

    /// Get next sibling of a node (Node::next_)
    static getNextSibling(nodeAddr) {
        var nodeHex = nodeAddr.toString().startsWith("0x") ? nodeAddr : "0x" + nodeAddr;
        var siblingCompressed = getCompressedMember(nodeHex, "(blink::Node*)", "next_");
        if (siblingCompressed === null) return null;
        return MemoryUtils.decompressCppgcPtr(siblingCompressed, nodeAddr);
    }

    /// Helper: Parse string from dx output
    static _parseStringFromDxOutput(output) {
        for (var line of output) {
            var s = line.toString();
            // Check for [AsciiText] : "value" or [Text] : "value"
            var match = s.match(/\[(Ascii)?Text\]\s*:\s*"([^"]+)"/);
            if (match) return match[2];
            // Check for "value" (simple quote)
            var match2 = s.match(/^"([^"]+)"$/);
            if (match2) return match2[1];
            // Fallback: look for any quoted string with Text label
            if (s.indexOf("Text") !== -1) {
                var m = s.match(/"([^"]+)"/);
                if (m) return m[1];
            }
        }
        return null;
    }

    /// Get node name (tag name)
    static getNodeName(nodeAddr) {
        var ctl = SymbolUtils.getControl();
        var nodeHex = nodeAddr.toString().startsWith("0x") ? nodeAddr : "0x" + nodeAddr;

        try {
            // Read node_flags_ to check type (avoid virtual calls)
            var cmd = "dx -r0 ((blink::Node*)" + nodeHex + ")->node_flags_";
            var output = ctl.ExecuteCommand(cmd);
            var flags = null;
            for (var line of output) {
                var s = line.toString();
                // Match decimal or hex from "node_flags_ : value"
                var m = s.match(/:\s*(0x[0-9a-fA-F]+|\d+)/);
                if (m) {
                    var valStr = m[1];
                    flags = valStr.startsWith("0x") ? parseInt(valStr, 16) : parseInt(valStr);
                    break;
                }
            }

            if (flags !== null) {
                var type = flags & 0xF;
                // kElementNode = 1
                if (type === 1) {
                    var cmdE = "dx -r2 ((blink::Element*)" + nodeHex + ")->tag_name_.impl_->local_name_";
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
    static _traverseAttributes(elementAddr, callback) {
        var elemHex;
        try {
            var s = elementAddr.toString();
            if (s.startsWith("0x")) elemHex = s;
            else if (/^\d+$/.test(s)) elemHex = "0x" + BigInt(s).toString(16);
            else elemHex = "0x" + s;
        } catch (e) { elemHex = "0x" + elementAddr; }

        var dataCompressed = getCompressedMember(elemHex, "(blink::Element*)", "element_data_");
        if (!dataCompressed || dataCompressed == 0n) return;

        var dataAddr = MemoryUtils.decompressCppgcPtr(dataCompressed, elemHex);
        if (!dataAddr || dataAddr === "0") return;

        var ctl = SymbolUtils.getControl();

        // Bitfield
        var bitField = 0;
        try {
            var cmd = "dx -r0 ((blink::ElementData*)0x" + dataAddr + ")->bit_field_.bits_";
            var output = ctl.ExecuteCommand(cmd);
            for (var line of output) {
                var m = line.toString().match(/:\s*(0x[0-9a-fA-F]+|\d+)/);
                if (m) {
                    var valStr = m[1];
                    bitField = valStr.startsWith("0x") ? parseInt(valStr, 16) : parseInt(valStr);
                    break;
                }
            }
        } catch (e) { }

        var isUnique = bitField & 1;
        var arraySize = (bitField >> 1) & 0xFFFFFFF;
        var count = isUnique ? 0 : arraySize;

        if (isUnique) {
            try {
                var sizeCmd = "dx -r0 ((blink::UniqueElementData*)0x" + dataAddr + ")->attribute_vector_.size_";
                var sizeOut = ctl.ExecuteCommand(sizeCmd);
                for (var line of sizeOut) {
                    var m = line.toString().match(/:\s*(\d+)/);
                    if (m) { count = parseInt(m[1]); break; }
                }
            } catch (e) { }
        }

        for (var i = 0; i < count; i++) {
            try {
                var base = isUnique
                    ? "((blink::UniqueElementData*)0x" + dataAddr + ")->attribute_vector_[" + i + "]"
                    : "((blink::ShareableElementData*)0x" + dataAddr + ")->attribute_array_[" + i + "]";

                var nameStr = "";
                var nCmd = "dx -r2 " + base + ".name_.impl_->local_name_";
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
            } catch (e) { }
        }
    }

    /// Get all attributes of an element as an array of objects
    static getAttributes(elementAddr) {
        var attrs = [];
        var ctl = SymbolUtils.getControl();

        BlinkUnwrap._traverseAttributes(elementAddr, (name, base) => {
            var valStr = "";
            var vOut = ctl.ExecuteCommand("dx -r2 " + base + ".value_");
            valStr = BlinkUnwrap._parseStringFromDxOutput(vOut);
            if (!valStr) {
                for (var line of vOut) {
                    var m = line.toString().match(/\"([^\"]*)\"/);
                    if (m) { valStr = m[1]; break; }
                    m = line.toString().match(/:\s*\.\s+(.+?)\s*\[Type/);
                    if (m) { valStr = m[1]; break; }
                }
            }
            attrs.push({ name: name, value: valStr || "" });
        });
        return attrs;
    }

    /// Get specific attribute value
    static getAttribute(elementAddr, attrName) {
        var val = null;
        var ctl = SymbolUtils.getControl();
        BlinkUnwrap._traverseAttributes(elementAddr, (name, base) => {
            if (name === attrName) {
                var vOut = ctl.ExecuteCommand("dx -r2 " + base + ".value_");
                val = BlinkUnwrap._parseStringFromDxOutput(vOut);
                if (!val) {
                    for (var line of vOut) {
                        var m = line.toString().match(/\"([^\"]*)\"/);
                        if (m) { val = m[1]; break; }
                    }
                }
                return true; // Stop
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
        var addr = nodeAddr.toString().startsWith("0x") ? nodeAddr : "0x" + nodeAddr;
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

/// Set an attribute value on an element (Direct Memory Modification)
function frame_setattr(elementAddr, attrName, attrValue) {
    if (isEmpty(elementAddr) || isEmpty(attrName)) {
        Logger.showUsage("Set Element Attribute", "!frame_setattr <element_addr> <attr_name> <attr_value>", [
            "!frame_setattr 0x12345678 \"id\" \"newId\"",
            "!frame_setattr 0x12345678 \"src\" \"https://example.com\""
        ]);
        Logger.info("Get element address from !frame_elem command first.");
        Logger.empty();
        return "";
    }

    var elemHex = elementAddr.toString().startsWith("0x") ? elementAddr : "0x" + elementAddr;
    var attr = attrName.replace(/"/g, "");
    var value = attrValue ? attrValue.replace(/"/g, "") : "";

    Logger.section("Set Attribute (Direct Memory): " + attr);
    Logger.info("Element: " + elemHex);
    Logger.info("Target Value: \"" + value + "\"");
    Logger.empty();

    var implAddr = BlinkUnwrap.findAttributeStringImplAddress(elemHex, attr);
    if (!implAddr || implAddr === "0") {
        Logger.error("Attribute '" + attr + "' not found on element.");
        Logger.info("This command modifies EXISTING attributes in memory.");
        Logger.info("To add a new attribute, the browser must allocate memory first.");
        return "";
    }

    Logger.info("Found StringImpl at: " + implAddr);

    // Check if new string fits (hacky safety check done in writeStringImpl)
    // If it's too long, it will be truncated.
    MemoryUtils.writeStringImpl(implAddr, value);

    Logger.info("Attribute value overwritten directly in memory.");
    Logger.info("Verify with !frame_getattr " + elemHex + " \"" + attr + "\"");

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
    if (!localFrame || localFrame === "0") {
        Logger.error("Could not get LocalFrame from WebLocalFrameImpl");
        return "";
    }
    Logger.info("LocalFrame:      0x" + localFrame);

    var domWindow = BlinkUnwrap.getDomWindow(localFrame);
    if (!domWindow || domWindow === "0") {
        Logger.error("Could not get LocalDOMWindow from LocalFrame");
        return "";
    }
    Logger.info("LocalDOMWindow:  0x" + domWindow);

    var document = BlinkUnwrap.getDocument(domWindow);
    if (!document || document === "0") {
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
    if (!localFrame || localFrame === "0") {
        Logger.error("Could not get LocalFrame from WebLocalFrameImpl");
        return "";
    }
    Logger.info("LocalFrame:      0x" + localFrame);

    var domWindow = BlinkUnwrap.getDomWindow(localFrame);
    if (!domWindow || domWindow === "0") {
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
    if (!localFrame || localFrame === "0") {
        Logger.error("Could not get LocalFrame from WebLocalFrameImpl");
        return "";
    }

    var domWindow = BlinkUnwrap.getDomWindow(localFrame);
    if (!domWindow || domWindow === "0") {
        Logger.error("Could not get LocalDOMWindow from LocalFrame");
        return "";
    }

    var document = BlinkUnwrap.getDocument(domWindow);
    if (!document || document === "0") {
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
    if (!localFrame || localFrame === "0") {
        Logger.error("Could not get LocalFrame from WebLocalFrameImpl");
        return "";
    }

    var document = BlinkUnwrap.getDocumentFromFrame(localFrame);
    if (!document || document === "0") {
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
            var MAX_NODES = 5000;

            while (stack.length > 0) {
                if (visited > MAX_NODES) {
                    Logger.warn("  Traversal limit reached (" + MAX_NODES + " nodes).");
                    break;
                }

                var node = stack.pop();
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
                if (sibling && sibling !== "0") {
                    stack.push(sibling);
                }

                // Only traverse children for ContainerNodes (skip text/comments/doctype)
                if (nodeName && nodeName !== "#text" && nodeName !== "#comment" && nodeName !== "#doctype") {
                    var child = BlinkUnwrap.getFirstChild(node);
                    if (child && child !== "0") {
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

/// Get an attribute value from an element
/// Get an attribute value from an element
function frame_getattr(elementAddr, attrName) {
    if (isEmpty(elementAddr) || isEmpty(attrName)) {
        Logger.showUsage("Get Element Attribute", "!frame_getattr <element_addr> <attr_name>", [
            "!frame_getattr 0x12345678 \"id\"",
            "!frame_getattr 0x12345678 \"src\""
        ]);
        Logger.info("Get element address from !frame_elem command first.");
        Logger.empty();
        return "";
    }

    var elemHex = elementAddr.toString().startsWith("0x") ? elementAddr : "0x" + elementAddr;
    var attr = attrName.replace(/"/g, "");

    Logger.section("Get Attribute: " + attr);
    Logger.info("Element: " + elemHex);
    Logger.empty();

    var val = BlinkUnwrap.getAttribute(elemHex, attr);
    if (val !== null) {
        Logger.info("Value: \"" + val + "\"");
        return val;
    }

    Logger.info("Attribute not found or empty.");
    Logger.empty();
    return "";
}





/// List all attributes of an element
function frame_attrs(elementAddr) {
    if (isEmpty(elementAddr)) {
        Logger.showUsage("Frame Attributes", "!frame_attrs <element_addr>", ["!frame_attrs 0x12345678"]);
        return "";
    }

    var attrs = BlinkUnwrap.getAttributes(elementAddr);

    Logger.section("Element Attributes: " + elementAddr);
    if (attrs.length === 0) {
        Logger.info("(No explicit attributes)");
    } else {
        for (var a of attrs) {
            Logger.info("  " + a.name + "=\"" + a.value + "\"");
        }
    }

    Logger.empty();
    return "";
}

/// Inspect a Blink Node/Object (Debugging helper)
function blink_unwrap(addrStr) {
    if (isEmpty(addrStr)) {
        Logger.showUsage("Blink Unwrap", "!blink_unwrap <address>", ["!blink_unwrap 0x12ac004e2340"]);
        return "";
    }

    try {
        BlinkUnwrap.inspectNode(addrStr);
    } catch (e) {
        Logger.error("Error in blink_unwrap: " + e.message);
    }

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
        return results;
    }

    static getInfoSafe(proc, sysId) {
        var cmdLine = "";
        var readSuccess = false;
        try {
            if (sysId !== undefined && sysId !== null && sysId !== "?") {
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

        var count = 0;
        for (var proc of processes) {
            if (proc.sysId === "?" || proc.sysId === null) continue;
            try {
                SymbolUtils.execute("|" + proc.sysId + "s");
                var result = callback(proc);
                count++;
                if (result === false) break;
            } catch (e) { Logger.error("Error in process " + proc.pid + ": " + e.message); }
        }
        try { SymbolUtils.execute("|0s"); } catch (e) { }
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
        new host.functionAlias(blink_unwrap, "blink_unwrap"),
        new host.functionAlias(decompress, "decompress"),
        new host.functionAlias(decompress_gc, "decompress_gc"),
        // Site Isolation
        new host.functionAlias(site_isolation_status, "site_iso"),
        // Per-Frame DOM Inspection
        new host.functionAlias(frame_document, "frame_doc"),
        new host.functionAlias(frame_window, "frame_win"),
        new host.functionAlias(frame_origin, "frame_origin"),
        new host.functionAlias(frame_elements, "frame_elem"),
        new host.functionAlias(frame_getattr, "frame_getattr"),
        new host.functionAlias(frame_setattr, "frame_setattr"),
        new host.functionAlias(frame_attrs, "frame_attrs")
    ];
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
    Logger.info("  !blink_unwrap(addr)   - Inspect Blink Node/Object");
    Logger.info("  !bp_element           - Break on DOM element creation");
    Logger.info("  !bp_nav               - Break on navigation");
    Logger.info("  !bp_pm                - Break on postMessage");
    Logger.info("  !bp_fetch             - Break on Fetch/XHR");
    Logger.empty();

    Logger.info("PER-FRAME DOM INSPECTION:");
    Logger.info("  !frame_doc(idx)       - Get Document for frame at index");
    Logger.info("  !frame_win(idx)       - Get LocalDOMWindow for frame at index");
    Logger.info("  !frame_origin(idx)    - Get SecurityOrigin for frame at index");
    Logger.info("  !frame_elem(idx,tag)  - List elements by tag name in frame");
    Logger.info("  !frame_getattr(el,a)  - Get attribute value from element");
    Logger.info("  !frame_setattr(el,a,v)- Set attribute value on element");
    Logger.info("  !frame_attrs(el)      - List all attributes of element");
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

    for (var proc of processes) {
        var pid = parseInt(proc.Id.toString());
        if (pidToSysId.has(pid)) {
            var sysId = pidToSysId.get(pid);
            var info = ProcessUtils.getInfoSafe(proc, sysId);
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
    var ctl = SymbolUtils.getControl();

    if (browserSysId === null || !childIds || childIds.length === 0) {
        return locks;
    }

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
        } catch (xErr) { return locks; }
        if (!funcAddr) return locks;

        // Step 2: Find a browser with chrome.dll and accessible singleton

        // Get all browser process IDs
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
                                    if (ptrVal !== "0" && ptrVal !== "00000000" && ptrVal.length > MIN_PTR_VALUE_LENGTH) {
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

        if (!instanceAddr) return locks;

        // Step 3: Enumerate all entries in security_state_ map
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
    } catch (e) { }

    return locks;
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
            var site = renderer_site();
            // renderer_site already prints output, but let's make it cleaner
        } catch (e) { }
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
    Logger.info(cmdLine.substring(0, 200) + "...");
    Logger.empty();

    return "";
}


// / List all Chrome processes in the debug session with site isolation info
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
    Logger.info("  Locked Site:        " + site);
    Logger.empty();

    return site;
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
    } else if (returnValue === "true" || returnValue === "TRUE" || returnValue === "True") {
        retVal = 1;
    } else if (returnValue === "false" || returnValue === "FALSE" || returnValue === "False") {
        retVal = 0;
    } else if (returnValue.toString().startsWith("0x") || returnValue.toString().startsWith("0X")) {
        retVal = parseInt(returnValue, 16);
    } else {
        retVal = parseInt(returnValue) || 0;
    }

    Logger.info("  Return value: " + retVal + (retVal === 0 ? " (false)" : retVal === 1 ? " (true)" : ""));
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

    // Get current origin from renderer_site
    Logger.info("  Target: " + targetOrigin);
    Logger.info("  Detecting current origin...");

    var currentOrigin = "";
    try {
        var site = renderer_site();
        if (site && site !== "" && site !== "(unknown)") {
            currentOrigin = site.replace(/\/+$/, "");
        }
    } catch (e) { }

    if (!currentOrigin) {
        Logger.empty();
        Logger.warn("Could not detect current origin.");
        Logger.info("Make sure you're in a renderer with a loaded page.");
        Logger.empty();
        return "";
    }

    // Parse current into scheme and host
    var currentMatch = currentOrigin.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(.+)$/);
    if (!currentMatch) {
        Logger.warn("Could not parse current origin: " + currentOrigin);
        return "";
    }
    var currentScheme = currentMatch[1];
    var currentHost = currentMatch[2];

    Logger.info("  Current: " + currentOrigin);
    Logger.info("  Current Host: " + currentHost + " -> Target Host: " + targetHost);
    Logger.empty();

    // Helper function to patch strings (ASCII or Unicode)
    function patchString(searchStr, replaceStr, label, isUnicode) {
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
                // optional: lessen noise by checking if we really expect it
                // Logger.info("  " + label + ": No " + (isUnicode ? "Unicode" : "ASCII") + " matches found");
                return 0;
            }

            var patched = 0;
            for (var addr of addresses) {
                try {
                    var byteStr = "";
                    for (var i = 0; i < replaceStr.length; i++) {
                        var code = replaceStr.charCodeAt(i);
                        if (isUnicode) {
                            byteStr += " " + (code & 0xFF).toString(16).padStart(2, '0');
                            byteStr += " " + ((code >> 8) & 0xFF).toString(16).padStart(2, '0');
                        } else {
                            byteStr += " " + code.toString(16).padStart(2, '0');
                        }
                    }

                    // Pad remainder with nulls
                    var charLen = isUnicode ? 2 : 1;
                    for (var k = replaceStr.length; k < searchStr.length; k++) {
                        byteStr += (isUnicode ? " 00 00" : " 00");
                    }

                    ctl.ExecuteCommand('eb 0x' + addr + byteStr);
                    patched++;
                } catch (e) { }
            }

            Logger.info("  " + label + ": Patched " + patched + "/" + addresses.length + " " + (isUnicode ? "Unicode" : "ASCII") + " occurrences");
            return patched;
        } catch (e) { return 0; }
    }

    var totalPatched = 0;

    // Patch protocol/scheme (SecurityOrigin's protocol_ field)
    if (currentScheme !== targetScheme) {
        totalPatched += patchString(currentScheme, targetScheme, "Scheme (ASCII)", false);
        totalPatched += patchString(currentScheme, targetScheme, "Scheme (Unicode)", true);
    } else {
        Logger.info("  Schemes are identical (" + currentScheme + "), skipping");
    }

    // Patch host (SecurityOrigin's host_ field)
    if (currentHost !== targetHost) {
        totalPatched += patchString(currentHost, targetHost, "Host (ASCII)", false);
        totalPatched += patchString(currentHost, targetHost, "Host (Unicode)", true);
    } else {
        Logger.info("  Hosts are identical (" + currentHost + "), skipping");
    }

    Logger.empty();
    Logger.info("  Total: Patched " + totalPatched + " locations");
    Logger.empty();

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

/// Check if current process is a renderer
function is_renderer() {
    var result = isProcessType("renderer");
    Logger.info("  Current process is " + (result ? "a RENDERER" : "NOT a renderer"));
    Logger.empty();
    return result;
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
            for (var sid in INTEGRITY_LEVELS) {
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
            if (integrity.length > 25) integrity = integrity.substring(0, 22) + "...";

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
        if (mapAddr && mapAddr !== "0000000000000000" && mapAddr !== "00000000") {
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
    var webFrameHex = f.webFrame.startsWith("0x") ? f.webFrame : "0x" + f.webFrame;
    var localFrameAddr = null;
    var frameCompressed = getCompressedMember(webFrameHex, "(blink::WebLocalFrameImpl*)", "frame_");
    if (frameCompressed !== null) {
        localFrameAddr = MemoryUtils.decompressCppgcPtr(frameCompressed, f.webFrame);
    }

    if (!localFrameAddr) return "";

    // Try via FrameLoader -> DocumentLoader
    var loaderCompressed = getCompressedMember("0x" + localFrameAddr, "(blink::LocalFrame*)", "loader_");
    if (loaderCompressed !== null) {
        var loaderAddr = MemoryUtils.decompressCppgcPtr(loaderCompressed, localFrameAddr);
        if (loaderAddr && loaderAddr !== "0" && loaderAddr !== "00000000") {
            var docLoaderCompressed = getCompressedMember("0x" + loaderAddr, "(blink::FrameLoader*)", "document_loader_");
            if (docLoaderCompressed !== null) {
                var docLoaderAddr = MemoryUtils.decompressCppgcPtr(docLoaderCompressed, loaderAddr);
                if (docLoaderAddr && docLoaderAddr !== "0" && docLoaderAddr !== "00000000") {
                    var url = readUrlStringFromDx(docLoaderAddr.toString(16), "(blink::DocumentLoader*)");
                    if (url) return url;
                }
            }
        }
    }

    // Fallback: Try via dom_window_ -> document_ -> url_
    var windowCompressed = getCompressedMember("0x" + localFrameAddr, "(blink::LocalFrame*)", "dom_window_");
    if (windowCompressed !== null) {
        var windowAddr = MemoryUtils.decompressCppgcPtr(windowCompressed, localFrameAddr);
        if (windowAddr && windowAddr !== "0" && windowAddr !== "00000000") {
            var docCompressed = getCompressedMember("0x" + windowAddr, "(blink::LocalDOMWindow*)", "document_");
            if (docCompressed !== null) {
                var docAddr = MemoryUtils.decompressCppgcPtr(docCompressed, windowAddr);
                if (docAddr && docAddr !== "0" && docAddr !== "00000000") {
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
    Logger.info("  [" + index + "] RenderFrameImpl:  " + f.renderFrame + " (ID: " + rfId + ")");
    Logger.info("       WebFrame:         " + f.webFrame);

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
            "chrome!mojo::ReportBadMessage",
            "chrome!mojo::ReportBadMessage",
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

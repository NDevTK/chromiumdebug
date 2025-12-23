host.diagnostics.debugLog("***> Starting Clipboard Permission Bypass Monitor \n");
function initialize() {
    var ctl = host.namespace.Debugger.Utility.Control;
    
    // Clear existing breakpoints
    ctl.ExecuteCommand("bc *");
    // 1. Hook the Safe Function (ReadText)
    // This logs when ReadText is called.
    ctl.ExecuteCommand('bp content!content::ClipboardHostImpl::ReadText "dx @$scriptContents.logCall(\\"ReadText\\"); g"');
    // 2. Hook the Vulnerable Function (ReadUnsanitizedCustomFormat)
    // This logs when the vulnerable IPC is received.
    ctl.ExecuteCommand('bp content!content::ClipboardHostImpl::ReadUnsanitizedCustomFormat "dx @$scriptContents.logCall(\\"ReadUnsanitizedCustomFormat\\"); g"');
    // 3. Hook the Permission Check (IsRendererPasteAllowed)
    // This logs when the browser actually verifies permission.
    ctl.ExecuteCommand('bp content!content::ClipboardHostImpl::IsRendererPasteAllowed "dx @$scriptContents.logCheck(); g"');
    host.diagnostics.debugLog("***> Breakpoints set. Waiting for IPC messages...\n");
    host.diagnostics.debugLog("***> EXPECTATION: ReadText should be followed by PermissionCheck. ReadUnsanitizedCustomFormat will NOT.\n");
    
    // Resume execution
    ctl.ExecuteCommand("g");
}
function logCall(funcName) {
    host.diagnostics.debugLog("\n***> [IPC] ClipboardHostImpl::" + funcName + " called.\n");
    if (funcName === "ReadUnsanitizedCustomFormat") {
         host.diagnostics.debugLog("***> [!] WATCH for missing permission check below [!]\n");
    }
}
function logCheck() {
    host.diagnostics.debugLog("***> [CHECK] IsRendererPasteAllowed called (Security Check Enforced)\n");
}
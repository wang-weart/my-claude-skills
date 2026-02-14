/* Trace function calls with arguments and return values using Interceptor. */

(function () {
    'use strict';

    var args = __frida_script_args || {};
    var functionNames = args.functions || [];
    var maxArgs = args.max_args || 4;
    var maxTraces = args.max_traces || 10000;

    if (functionNames.length === 0) {
        console.log('[!] No functions specified. Pass: {"functions":["open","read","write"]}');
        console.log('[!] You can also pass addresses: {"functions":["0x401234"]}');
        return;
    }

    var traces = [];
    var traceCount = 0;

    function resolveFunction(nameOrAddr) {
        // Try as hex address first
        if (nameOrAddr.startsWith('0x') || nameOrAddr.startsWith('0X')) {
            return { name: nameOrAddr, address: ptr(nameOrAddr) };
        }

        // Try to find in exports
        var addr = Module.findExportByName(null, nameOrAddr);
        if (addr) {
            return { name: nameOrAddr, address: addr };
        }

        // Try DebugSymbol
        try {
            var resolved = DebugSymbol.fromName(nameOrAddr);
            if (resolved && !resolved.address.isNull()) {
                return { name: nameOrAddr, address: resolved.address };
            }
        } catch (e) { /* ignore */ }

        return null;
    }

    for (var i = 0; i < functionNames.length; i++) {
        var funcName = functionNames[i];
        var resolved = resolveFunction(funcName);

        if (!resolved) {
            console.log('[!] Could not resolve: ' + funcName);
            continue;
        }

        console.log('[*] Hooking ' + resolved.name + ' at ' + resolved.address);

        (function (name, address) {
            Interceptor.attach(address, {
                onEnter: function (fnArgs) {
                    if (traceCount >= maxTraces) return;

                    this._name = name;
                    this._args = [];
                    for (var a = 0; a < maxArgs; a++) {
                        this._args.push(fnArgs[a].toString());
                    }
                    this._tid = Process.getCurrentThreadId();
                    this._timestamp = Date.now();

                    // Get backtrace
                    this._backtrace = [];
                    try {
                        var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                        for (var b = 0; b < Math.min(bt.length, 5); b++) {
                            var sym = DebugSymbol.fromAddress(bt[b]);
                            this._backtrace.push(sym.toString());
                        }
                    } catch (e) { /* ignore */ }
                },
                onLeave: function (retval) {
                    if (traceCount >= maxTraces) return;

                    var entry = {
                        function: this._name,
                        args: this._args,
                        retval: retval.toString(),
                        thread_id: this._tid,
                        timestamp: this._timestamp,
                        backtrace: this._backtrace,
                    };

                    traces.push(entry);
                    traceCount++;

                    console.log('[TRACE] ' + this._name + '(' +
                        this._args.join(', ') + ') => ' + retval);
                },
            });
        })(resolved.name, resolved.address);
    }

    console.log('[*] Tracing ' + functionNames.length + ' function(s). Press Ctrl+C to stop.');
    console.log('[*] Max traces: ' + maxTraces);

    // Write results on script unload
    Script.bindWeak(Script, function () {
        var result = {
            traced_functions: functionNames,
            trace_count: traces.length,
            traces: traces,
        };
        __writeOutput(__frida_process_name + '_trace.json', result);
    });

    // Also periodically flush
    setInterval(function () {
        if (traces.length > 0) {
            var result = {
                traced_functions: functionNames,
                trace_count: traces.length,
                traces: traces,
            };
            __writeOutput(__frida_process_name + '_trace.json', result);
        }
    }, 5000);
})();

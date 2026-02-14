/* Instruction-level code tracing using Frida's Stalker engine. */

(function () {
    'use strict';

    var args = __frida_script_args || {};
    var targetFunction = args.function || null;
    var targetAddr = args.address || null;
    var maxBlocks = args.max_blocks || 50000;
    var timeout = args.timeout || 30;

    if (!targetFunction && !targetAddr) {
        console.log('[!] No target specified.');
        console.log('[!] Pass: {"function":"main"} or {"address":"0x401234"}');
        console.log('[!] Optional: {"max_blocks":50000, "timeout":30}');
        return;
    }

    // Resolve the target address
    var funcAddr;
    var funcName;

    if (targetAddr) {
        funcAddr = ptr(targetAddr);
        funcName = targetAddr;
    } else {
        var resolved = Module.findExportByName(null, targetFunction);
        if (!resolved) {
            // Try DebugSymbol
            try {
                var sym = DebugSymbol.fromName(targetFunction);
                if (sym && !sym.address.isNull()) {
                    resolved = sym.address;
                }
            } catch (e) { /* ignore */ }
        }

        if (!resolved) {
            console.log('[!] Could not resolve function: ' + targetFunction);
            return;
        }
        funcAddr = resolved;
        funcName = targetFunction;
    }

    console.log('[*] Stalker tracing ' + funcName + ' at ' + funcAddr);
    console.log('[*] Max blocks: ' + maxBlocks + ', timeout: ' + timeout + 's');

    var blocksVisited = {};
    var callTargets = [];
    var blockCount = 0;
    var instructionCount = 0;
    var tracing = false;
    var traceTid = null;

    // Hook the target function to start stalking on its thread
    Interceptor.attach(funcAddr, {
        onEnter: function () {
            if (tracing) return;
            tracing = true;
            traceTid = Process.getCurrentThreadId();

            console.log('[*] Function entered on thread ' + traceTid + ', starting Stalker...');

            Stalker.follow(traceTid, {
                events: {
                    call: true,
                    ret: false,
                    exec: false,
                    block: true,
                    compile: false,
                },

                onReceive: function (events) {
                    var parsed = Stalker.parse(events, {
                        annotate: true,
                        stringify: true,
                    });

                    for (var i = 0; i < parsed.length && blockCount < maxBlocks; i++) {
                        var event = parsed[i];

                        if (event[0] === 'block') {
                            var blockStart = event[1];
                            var blockEnd = event[2];

                            if (!blocksVisited[blockStart]) {
                                blocksVisited[blockStart] = {
                                    start: blockStart,
                                    end: blockEnd,
                                    hit_count: 0,
                                };
                                blockCount++;
                            }
                            blocksVisited[blockStart].hit_count++;
                        } else if (event[0] === 'call') {
                            var from = event[1];
                            var to = event[2];
                            callTargets.push({ from: from, to: to });
                        }
                    }
                },
            });
        },

        onLeave: function () {
            if (!tracing) return;
            console.log('[*] Function returned, stopping Stalker...');
            Stalker.unfollow(traceTid);
            Stalker.flush();
            tracing = false;
            writeResults();
        },
    });

    function writeResults() {
        // Determine which modules were touched
        var moduleCoverage = {};
        var blockList = Object.values(blocksVisited);

        for (var i = 0; i < blockList.length; i++) {
            var block = blockList[i];
            try {
                var mod = Process.findModuleByAddress(ptr(block.start));
                if (mod) {
                    if (!moduleCoverage[mod.name]) {
                        moduleCoverage[mod.name] = { blocks: 0, name: mod.name };
                    }
                    moduleCoverage[mod.name].blocks++;
                }
            } catch (e) { /* ignore */ }
        }

        // Resolve call targets
        var resolvedCalls = [];
        for (var j = 0; j < Math.min(callTargets.length, 10000); j++) {
            var call = callTargets[j];
            var targetName = null;
            try {
                var sym = DebugSymbol.fromAddress(ptr(call.to));
                if (sym) targetName = sym.toString();
            } catch (e) { /* ignore */ }

            resolvedCalls.push({
                from: call.from,
                to: call.to,
                target_name: targetName,
            });
        }

        var result = {
            target_function: funcName,
            target_address: funcAddr.toString(),
            blocks_visited: blockCount,
            total_calls: callTargets.length,
            module_coverage: moduleCoverage,
            blocks: blockList.slice(0, maxBlocks),
            calls: resolvedCalls,
        };

        console.log('[*] Stalker results:');
        console.log('  Blocks visited: ' + blockCount);
        console.log('  Call targets: ' + callTargets.length);
        console.log('  Modules touched: ' + Object.keys(moduleCoverage).length);

        __writeOutput(__frida_process_name + '_stalker.json', result);
    }

    // Safety timeout
    setTimeout(function () {
        if (tracing) {
            console.log('[*] Timeout reached, stopping Stalker...');
            Stalker.unfollow(traceTid);
            Stalker.flush();
            tracing = false;
            writeResults();
        }
    }, timeout * 1000);

    console.log('[*] Waiting for ' + funcName + ' to be called... (timeout: ' + timeout + 's)');
})();

/* Hook functions to log or modify behavior. */

(function () {
    'use strict';

    var args = __frida_script_args || {};
    var functionNames = args.functions || [];
    var action = args.action || 'log';  // log, replace_retval, skip
    var replaceRetval = args.retval || null;

    if (functionNames.length === 0) {
        console.log('[!] No functions specified.');
        console.log('[!] Pass: {"functions":["malloc","free"], "action":"log"}');
        console.log('[!] Actions: log, replace_retval (with "retval":"0x1"), skip');
        return;
    }

    var hookLog = [];

    function resolveFunction(nameOrAddr) {
        if (nameOrAddr.startsWith('0x') || nameOrAddr.startsWith('0X')) {
            return { name: nameOrAddr, address: ptr(nameOrAddr) };
        }
        var addr = Module.findExportByName(null, nameOrAddr);
        if (addr) {
            return { name: nameOrAddr, address: addr };
        }
        return null;
    }

    for (var i = 0; i < functionNames.length; i++) {
        var funcName = functionNames[i];
        var resolved = resolveFunction(funcName);

        if (!resolved) {
            console.log('[!] Could not resolve: ' + funcName);
            continue;
        }

        console.log('[*] Hooking ' + resolved.name + ' at ' + resolved.address + ' (action: ' + action + ')');

        (function (name, address) {
            Interceptor.attach(address, {
                onEnter: function (fnArgs) {
                    this._name = name;
                    this._args = [];
                    for (var a = 0; a < 4; a++) {
                        this._args.push(fnArgs[a].toString());
                    }

                    if (action === 'log' || __frida_verbose) {
                        console.log('[HOOK] ' + name + ' called with: ' + this._args.join(', '));
                    }

                    var entry = {
                        function: name,
                        event: 'enter',
                        args: this._args,
                        thread_id: Process.getCurrentThreadId(),
                        timestamp: Date.now(),
                    };
                    hookLog.push(entry);
                },
                onLeave: function (retval) {
                    var origRetval = retval.toString();

                    if (action === 'replace_retval' && replaceRetval !== null) {
                        retval.replace(ptr(replaceRetval));
                        console.log('[HOOK] ' + this._name + ' retval replaced: ' + origRetval + ' -> ' + replaceRetval);
                    } else if (action === 'skip') {
                        retval.replace(ptr(0));
                        console.log('[HOOK] ' + this._name + ' skipped (retval = 0)');
                    } else {
                        console.log('[HOOK] ' + this._name + ' returned: ' + origRetval);
                    }

                    hookLog.push({
                        function: this._name,
                        event: 'leave',
                        original_retval: origRetval,
                        action: action,
                        thread_id: Process.getCurrentThreadId(),
                        timestamp: Date.now(),
                    });
                },
            });
        })(resolved.name, resolved.address);
    }

    console.log('[*] Hooks active. Press Ctrl+C to stop.');

    Script.bindWeak(Script, function () {
        __writeOutput(__frida_process_name + '_hooks.json', {
            hooked_functions: functionNames,
            action: action,
            event_count: hookLog.length,
            events: hookLog,
        });
    });

    setInterval(function () {
        if (hookLog.length > 0) {
            __writeOutput(__frida_process_name + '_hooks.json', {
                hooked_functions: functionNames,
                action: action,
                event_count: hookLog.length,
                events: hookLog,
            });
        }
    }, 5000);
})();

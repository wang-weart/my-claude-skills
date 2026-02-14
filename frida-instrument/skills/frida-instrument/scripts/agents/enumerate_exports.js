/* List exports from a specific module or the main module. */

(function () {
    'use strict';

    var args = __frida_script_args || {};
    var targetModule = args.module || null;

    var result = { module: null, exports: [] };

    if (targetModule) {
        result.module = targetModule;
        try {
            var exports = Module.enumerateExports(targetModule);
            for (var i = 0; i < exports.length && i < 10000; i++) {
                result.exports.push({
                    name: exports[i].name,
                    type: exports[i].type,
                    address: exports[i].address.toString(),
                });
            }
        } catch (e) {
            console.log('[!] Error enumerating exports for ' + targetModule + ': ' + e.message);
            result.error = e.message;
        }
    } else {
        // Enumerate exports from all modules
        var modules = Process.enumerateModules();
        result.module = 'all';
        result.by_module = {};

        for (var m = 0; m < modules.length; m++) {
            var mod = modules[m];
            try {
                var modExports = mod.enumerateExports();
                var exportList = [];
                for (var j = 0; j < modExports.length && j < 5000; j++) {
                    exportList.push({
                        name: modExports[j].name,
                        type: modExports[j].type,
                        address: modExports[j].address.toString(),
                    });
                    result.exports.push({
                        name: modExports[j].name,
                        type: modExports[j].type,
                        address: modExports[j].address.toString(),
                        module: mod.name,
                    });
                }
                if (exportList.length > 0) {
                    result.by_module[mod.name] = exportList.length;
                }
            } catch (e) {
                // Skip modules that can't be enumerated
            }

            if (result.exports.length >= 50000) break;
        }
    }

    console.log('[*] Found ' + result.exports.length + ' exports');
    __writeOutput(__frida_process_name + '_exports.json', result);
})();

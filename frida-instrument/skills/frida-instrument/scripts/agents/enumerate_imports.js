/* List imports from a specific module or the main module. */

(function () {
    'use strict';

    var args = __frida_script_args || {};
    var targetModule = args.module || null;

    var result = { module: null, imports: [] };

    if (targetModule) {
        result.module = targetModule;
        try {
            var imports = Module.enumerateImports(targetModule);
            for (var i = 0; i < imports.length && i < 10000; i++) {
                result.imports.push({
                    name: imports[i].name,
                    type: imports[i].type,
                    module: imports[i].module || null,
                    address: imports[i].address ? imports[i].address.toString() : null,
                });
            }
        } catch (e) {
            console.log('[!] Error: ' + e.message);
            result.error = e.message;
        }
    } else {
        // Use main module
        var modules = Process.enumerateModules();
        if (modules.length > 0) {
            var mainMod = modules[0];
            result.module = mainMod.name;
            try {
                var mainImports = mainMod.enumerateImports();
                for (var j = 0; j < mainImports.length && j < 10000; j++) {
                    result.imports.push({
                        name: mainImports[j].name,
                        type: mainImports[j].type,
                        module: mainImports[j].module || null,
                        address: mainImports[j].address ? mainImports[j].address.toString() : null,
                    });
                }
            } catch (e) {
                result.error = e.message;
            }
        }
    }

    console.log('[*] Found ' + result.imports.length + ' imports from ' + result.module);
    __writeOutput(__frida_process_name + '_imports.json', result);
})();

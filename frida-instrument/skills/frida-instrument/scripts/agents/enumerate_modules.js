/* List all loaded modules with base addresses, sizes, and file paths. */

(function () {
    'use strict';

    var modules = Process.enumerateModules();
    var result = [];

    for (var i = 0; i < modules.length; i++) {
        var mod = modules[i];
        result.push({
            name: mod.name,
            base: mod.base.toString(),
            size: mod.size,
            end: mod.base.add(mod.size).toString(),
            path: mod.path,
        });
    }

    console.log('[*] Found ' + result.length + ' loaded modules');
    for (var j = 0; j < Math.min(result.length, 20); j++) {
        console.log('  ' + result[j].base + ' ' + result[j].name + ' (' + result[j].size + ' bytes)');
    }
    if (result.length > 20) {
        console.log('  ... and ' + (result.length - 20) + ' more');
    }

    __writeOutput(__frida_process_name + '_modules.json', result);
})();

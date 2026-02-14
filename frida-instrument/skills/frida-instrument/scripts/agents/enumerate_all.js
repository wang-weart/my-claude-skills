/* Comprehensive runtime enumeration of the attached/spawned process. */

(function () {
    'use strict';

    var result = {
        process: {
            id: Process.id,
            arch: Process.arch,
            platform: Process.platform,
            pageSize: Process.pageSize,
            pointerSize: Process.pointerSize,
        },
        modules: [],
        main_exports: [],
        main_imports: [],
        memory_ranges: [],
    };

    // Enumerate all loaded modules
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var mod = modules[i];
        result.modules.push({
            name: mod.name,
            base: mod.base.toString(),
            size: mod.size,
            path: mod.path,
        });
    }

    // Main module exports
    if (modules.length > 0) {
        var mainModule = modules[0];
        try {
            var exports = mainModule.enumerateExports();
            for (var j = 0; j < exports.length && j < 5000; j++) {
                result.main_exports.push({
                    name: exports[j].name,
                    type: exports[j].type,
                    address: exports[j].address.toString(),
                });
            }
        } catch (e) {
            result.main_exports_error = e.message;
        }

        // Main module imports
        try {
            var imports = mainModule.enumerateImports();
            for (var k = 0; k < imports.length && k < 5000; k++) {
                result.main_imports.push({
                    name: imports[k].name,
                    type: imports[k].type,
                    module: imports[k].module || null,
                    address: imports[k].address ? imports[k].address.toString() : null,
                });
            }
        } catch (e) {
            result.main_imports_error = e.message;
        }
    }

    // Memory ranges
    var ranges = Process.enumerateRanges('---');
    for (var r = 0; r < ranges.length && r < 2000; r++) {
        var range = ranges[r];
        result.memory_ranges.push({
            base: range.base.toString(),
            size: range.size,
            protection: range.protection,
            file: range.file ? range.file.path : null,
        });
    }

    result.summary = {
        module_count: result.modules.length,
        main_export_count: result.main_exports.length,
        main_import_count: result.main_imports.length,
        memory_range_count: result.memory_ranges.length,
    };

    console.log(JSON.stringify(result.summary, null, 2));
    __writeOutput(__frida_process_name + '_enumeration.json', result);

    // Exit cleanly after enumeration
    setTimeout(function () { /* allow file write to complete */ }, 500);
})();

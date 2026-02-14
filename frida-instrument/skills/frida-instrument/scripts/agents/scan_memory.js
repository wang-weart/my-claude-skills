/* Scan process memory for byte patterns or strings. */

(function () {
    'use strict';

    var args = __frida_script_args || {};
    var hexPattern = args.pattern || null;   // e.g. "48 89 5c 24 ??"
    var stringPattern = args.string || null; // e.g. "password"
    var maxResults = args.max_results || 1000;

    if (!hexPattern && !stringPattern) {
        console.log('[!] No pattern specified.');
        console.log('[!] Pass: {"pattern":"48 89 5c 24 ??"} for hex pattern with wildcards');
        console.log('[!]   or: {"string":"password"} for string search');
        return;
    }

    // Convert string to hex pattern if needed
    var scanPattern;
    if (stringPattern) {
        var hexBytes = [];
        for (var c = 0; c < stringPattern.length; c++) {
            hexBytes.push(('0' + stringPattern.charCodeAt(c).toString(16)).slice(-2));
        }
        scanPattern = hexBytes.join(' ');
        console.log('[*] Scanning for string: "' + stringPattern + '" (pattern: ' + scanPattern + ')');
    } else {
        scanPattern = hexPattern;
        console.log('[*] Scanning for pattern: ' + scanPattern);
    }

    var results = [];
    var ranges = Process.enumerateRanges('r--');

    console.log('[*] Scanning ' + ranges.length + ' readable memory ranges...');

    for (var i = 0; i < ranges.length; i++) {
        if (results.length >= maxResults) break;

        var range = ranges[i];

        try {
            var matches = Memory.scanSync(range.base, range.size, scanPattern);

            for (var j = 0; j < matches.length && results.length < maxResults; j++) {
                var match = matches[j];

                // Get context: which module does this address belong to?
                var moduleInfo = null;
                try {
                    var mod = Process.findModuleByAddress(match.address);
                    if (mod) {
                        moduleInfo = {
                            name: mod.name,
                            offset: match.address.sub(mod.base).toString(),
                        };
                    }
                } catch (e) { /* ignore */ }

                // Read surrounding context
                var context = '';
                try {
                    var contextBytes = match.address.readByteArray(Math.min(64, range.size));
                    if (contextBytes) {
                        var arr = new Uint8Array(contextBytes);
                        var printable = [];
                        for (var b = 0; b < arr.length; b++) {
                            if (arr[b] >= 0x20 && arr[b] <= 0x7e) {
                                printable.push(String.fromCharCode(arr[b]));
                            } else {
                                printable.push('.');
                            }
                        }
                        context = printable.join('');
                    }
                } catch (e) { /* ignore */ }

                results.push({
                    address: match.address.toString(),
                    size: match.size,
                    module: moduleInfo,
                    context: context,
                    range_protection: range.protection,
                });
            }
        } catch (e) {
            // Skip unreadable ranges
        }
    }

    console.log('[*] Found ' + results.length + ' matches');
    for (var k = 0; k < Math.min(results.length, 20); k++) {
        var r = results[k];
        var modStr = r.module ? ' (' + r.module.name + '+' + r.module.offset + ')' : '';
        console.log('  ' + r.address + modStr + ': ' + r.context.substring(0, 40));
    }
    if (results.length > 20) {
        console.log('  ... and ' + (results.length - 20) + ' more');
    }

    __writeOutput(__frida_process_name + '_scan_results.json', {
        pattern: hexPattern || null,
        string: stringPattern || null,
        scan_pattern: scanPattern,
        match_count: results.length,
        matches: results,
    });
})();

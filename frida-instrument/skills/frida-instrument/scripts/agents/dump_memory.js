/* Dump memory regions: specific address+size, or entire module. */

(function () {
    'use strict';

    var args = __frida_script_args || {};
    var targetModule = args.module || null;
    var targetAddr = args.address || null;
    var targetSize = args.size || 4096;

    if (!targetModule && !targetAddr) {
        console.log('[!] No target specified.');
        console.log('[!] Pass: {"module":"libfoo.so"} or {"address":"0x7fff1000","size":4096}');
        console.log('[*] Listing readable memory ranges instead...');

        var ranges = Process.enumerateRanges('r--');
        var rangeInfo = [];
        for (var i = 0; i < ranges.length && i < 200; i++) {
            rangeInfo.push({
                base: ranges[i].base.toString(),
                size: ranges[i].size,
                protection: ranges[i].protection,
                file: ranges[i].file ? ranges[i].file.path : null,
            });
        }

        __writeOutput(__frida_process_name + '_memory_ranges.json', rangeInfo);
        console.log('[*] Listed ' + rangeInfo.length + ' readable ranges');
        return;
    }

    var baseAddr, size, label;

    if (targetModule) {
        var mod = Process.findModuleByName(targetModule);
        if (!mod) {
            console.log('[!] Module not found: ' + targetModule);
            return;
        }
        baseAddr = mod.base;
        size = Math.min(mod.size, args.size || mod.size);
        label = targetModule;
        console.log('[*] Dumping module ' + targetModule + ' at ' + baseAddr + ' (' + size + ' bytes)');
    } else {
        baseAddr = ptr(targetAddr);
        size = targetSize;
        label = targetAddr;
        console.log('[*] Dumping ' + size + ' bytes at ' + baseAddr);
    }

    // Hex dump
    try {
        var hexOutput = hexdump(baseAddr, {
            offset: 0,
            length: Math.min(size, 1024 * 1024),  // Cap at 1MB for hex
            header: true,
            ansi: false,
        });

        __writeRawOutput(__frida_process_name + '_memdump.txt', hexOutput);
        console.log('[*] Hex dump written (' + Math.min(size, 1024 * 1024) + ' bytes)');
    } catch (e) {
        console.log('[!] Hex dump failed: ' + e.message);
    }

    // Raw binary dump
    try {
        var rawData = baseAddr.readByteArray(Math.min(size, 10 * 1024 * 1024));
        if (rawData) {
            __writeBinaryOutput(__frida_process_name + '_memdump.bin', rawData);
            console.log('[*] Raw dump written');
        }
    } catch (e) {
        console.log('[!] Raw dump failed: ' + e.message);
    }
})();

#!/bin/bash

APP="owasp.mstg.uncrackable3"
ACTIVITY="sg.vantagepoint.uncrackable3.MainActivity"
TMP_SCRIPT="/tmp/Clean-Bypass_tmp.js"
PORT="12345"

echo "[*] 0. Generando el script directamente en la RAM..."
cat << 'EOF' > "$TMP_SCRIPT"
// Programa en JavaScript para bypassear el exit al detectar root
Java.perform(function () {
        var RootDetection = Java.use("sg.vantagepoint.util.RootDetection");
        RootDetection.checkRoot1.implementation = function(){ return false; };
        RootDetection.checkRoot2.implementation = function(){ return false; };
        RootDetection.checkRoot3.implementation = function(){ return false; };

        var System = Java.use('java.lang.System');
        System.exit.implementation = function(code){
                console.log("[+] Intento de cierre bloqueado.");
        };

        var Runtime = Java.use('java.lang.Runtime');
        Runtime.loadLibrary0.overload('java.lang.Class', 'java.lang.String').implementation = function(fromClass, libraryName) {
                this.loadLibrary0(fromClass, libraryName);
                if (libraryName === 'foo') {
                        console.log("[+] libfoo.so cargada. Aplicando sedante...");
                        var moduloFoo = Process.findModuleByName("libfoo.so");
                        if (moduloFoo !== null) {
                                var goodbye_ptr = moduloFoo.base.add(0x3000);
                                try {
                                        Memory.protect(goodbye_ptr, 2, 'rwx');
                                        goodbye_ptr.writeU8(0xeb); 
                                        goodbye_ptr.add(1).writeU8(0xfe); 
                                        console.log("[*] goodbye() neutralizado.");
                                } catch (e) {
                                        console.log("[-] Error parche: " + e);
                                }
                        }
                }
        };
});

// CAZADOR DE BANDERAS 3.0: Hook síncrono ultra-estable
var strncmpPtr = Module.findExportByName(null, "strncmp");

if (strncmpPtr) {
    Interceptor.attach(strncmpPtr, {
        onEnter: function (args) {
            var size = args[2].toInt32();
            if (size === 24) {
                console.log("\n[!!!] COMPARACION DE 24 DETECTADA [!!!]");
                try {
                    console.log("TEXTO A: " + args[0].readUtf8String(24));
                    console.log("TEXTO B: " + args[1].readUtf8String(24));
                } catch(e) {
                    // Si no es UTF8, lo sacamos en Hexdump
                    console.log("HEX A:\n" + hexdump(args[0], {length: 24}));
                    console.log("HEX B:\n" + hexdump(args[1], {length: 24}));
                }
            }
        }
    });
    console.log("[*] Gancho puesto. Escribe los 24 caracteres y pulsa VERIFY.");
}
EOF

echo "[*] 1. Arrancando la aplicacion..."
adb shell am start -D -n $APP/$ACTIVITY > /dev/null 2>&1
sleep 1
PID=$(adb shell pidof $APP | tr -d '\r')
echo "[+] PID: $PID"
adb forward tcp:$PORT jdwp:$PID

echo "================================================================="
echo "[!] Ejecuta en otra pestaña: jdb -attach localhost:$PORT"
echo "================================================================="

frida -U -p $PID -l "$TMP_SCRIPT"

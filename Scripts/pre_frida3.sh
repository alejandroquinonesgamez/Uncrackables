#!/bin/bash

APP="owasp.mstg.uncrackable3"
ACTIVITY="sg.vantagepoint.uncrackable3.MainActivity"
TMP_SCRIPT="/tmp/Final_Dragnet.js"
PORT="12345"

echo "[*] 0. Generando Red de Arrastre Nativa..."
cat << 'EOF' > "$TMP_SCRIPT"
Java.perform(function () {
        // --- 1. SUPERVIVENCIA (ROOT & EXIT) ---
        var RootDetection = Java.use("sg.vantagepoint.util.RootDetection");
        RootDetection.checkRoot1.implementation = function(){ return false; };
        RootDetection.checkRoot2.implementation = function(){ return false; };
        RootDetection.checkRoot3.implementation = function(){ return false; };
        Java.use('java.lang.System').exit.implementation = function(code){};

        // --- 2. SEDANTE NATIVO ---
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.loadLibrary0.overload('java.lang.Class', 'java.lang.String').implementation = function(fromClass, libraryName) {
                this.loadLibrary0(fromClass, libraryName);
                if (libraryName === 'foo') {
                        var moduloFoo = Process.findModuleByName("libfoo.so");
                        if (moduloFoo) {
                                // Parcheamos goodbye() (Offset 0x3000)
                                var goodbye_ptr = moduloFoo.base.add(0x3000);
                                Memory.protect(goodbye_ptr, 2, 'rwx');
                                goodbye_ptr.writeU8(0xeb); 
                                goodbye_ptr.add(1).writeU8(0xfe);
                                console.log("[***] APP ESTABLE [***]");

                                // --- 3. RED DE ARRASTRE (Hooking a ciegas) ---
                                // Listamos todas las funciones que exporta la librería
                                var exports = moduloFoo.enumerateExports();
                                exports.forEach(function(exp) {
                                        if (exp.type === 'function') {
                                                Interceptor.attach(exp.address, {
                                                        onEnter: function(args) {
                                                                console.log("\n[*] LLAMADA A FUNCION: " + exp.name);
                                                                // Intentamos leer los primeros 3 argumentos como si fueran punteros a la bandera
                                                                for (var i = 0; i < 3; i++) {
                                                                        try {
                                                                                var str = args[i].readUtf8String(24);
                                                                                if (str && str.length >= 10) {
                                                                                        console.log("    [!] Posible Bandera en Arg["+i+"]: " + str);
                                                                                }
                                                                        } catch(e) {}
                                                                }
                                                        }
                                                });
                                        }
                                });
                                console.log("[*] Red de arrastre desplegada sobre libfoo.so.");
                        }
                }
        };
});
EOF

echo "[*] 1. Lanzando..."
adb shell am start -D -n $APP/$ACTIVITY > /dev/null 2>&1
sleep 1
PID=$(adb shell pidof $APP | tr -d '\r')
adb forward tcp:$PORT jdwp:$PID
echo "================================================================="
echo "[!] JDB -attach localhost:$PORT"
echo "================================================================="
frida -U -p $PID -l "$TMP_SCRIPT"

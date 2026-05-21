#!/bin/bash

APP="owasp.mstg.uncrackable3"
ACTIVITY="sg.vantagepoint.uncrackable3.MainActivity"
TMP_SCRIPT="/tmp/Clean-Bypass_tmp.js"
PORT="12345"

echo "[*] 0. Generando el script directamente en la RAM..."
cat << 'EOF' > "$TMP_SCRIPT"
// Programa en JavaScript para bypassear el exit al detectar root
Java.perform(function () {
        // Enlazamos con las funciones de detección de Root de la aplicación
        var RootDetection = Java.use("sg.vantagepoint.util.RootDetection");
        
        // Aquí se añade el código para bypassear las diferentes comprobaciones de root
        RootDetection.checkRoot1.implementation = function(){ return false; };
        RootDetection.checkRoot2.implementation = function(){ return false; };
        RootDetection.checkRoot3.implementation = function(){ return false; };

        // Enlazamos con el System de Android
        var System = Java.use('java.lang.System');
        // Evitamos el cierre de la aplicación
        System.exit.implementation = function(code){
                console.log("[+] Intento de cierre bloqueado.");
        };

        // Congelamos el tiempo justo en la carga de la librería
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.loadLibrary0.overload('java.lang.Class', 'java.lang.String').implementation = function(fromClass, libraryName) {
                // Dejamos que Android cargue la librería en la memoria
                this.loadLibrary0(fromClass, libraryName);
                
                if (libraryName === 'foo') {
                        console.log("[+] libfoo.so cargada. Aplicando sedante al hilo...");
                        
                        var moduloFoo = Process.findModuleByName("libfoo.so");
                        if (moduloFoo !== null) {
                                // Tu cálculo inamovible
                                var goodbye_ptr = moduloFoo.base.add(0x3000);
                                
                                try {
                                        Memory.protect(goodbye_ptr, 2, 'rwx'); // Damos permiso para 2 bytes
                                        // Escribimos EB FE (Bucle infinito en x86)
                                        goodbye_ptr.writeU8(0xeb); 
                                        goodbye_ptr.add(1).writeU8(0xfe); 
                                        console.log("[*] ¡goodbye() neutralizado! (Hilo congelado con EB FE)");
                                } catch (e) {
                                        console.log("[-] Error parcheando la memoria: " + e);
                                }
                        }
                }
        };
});
EOF

echo "[*] 1. Arrancando la aplicacion en modo Debug..."
adb shell am start -D -n $APP/$ACTIVITY > /dev/null 2>&1

sleep 1

echo "[*] 2. Buscando el PID de la aplicacion..."
PID=$(adb shell pidof $APP | tr -d '\r')

if [ -z "$PID" ]; then
    echo "[-] ERROR: No se ha podido encontrar el proceso. Revisa tu conexion."
    exit 1
fi

echo "[+] PID capturado: $PID"

echo "[*] 3. Creando tunel JDWP en el puerto local $PORT..."
adb forward tcp:$PORT jdwp:$PID

echo "================================================================="
echo "[!] ATENCION: Cuando Frida termine de conectar, abre otra pestana"
echo "[!] y ejecuta: jdb -attach localhost:$PORT"
echo "================================================================="
echo "[*] 4. Inyectando Frida..."

frida -U -p $PID -l "$TMP_SCRIPT"

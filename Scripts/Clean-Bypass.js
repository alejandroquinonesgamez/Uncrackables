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
});

// Bypass de la detección comprobando la memoria en segundo plano
var francotirador = setInterval(function() {
        var moduloFoo = Process.findModuleByName("libfoo.so");
        
        if (moduloFoo !== null) {
                clearInterval(francotirador);
                console.log("[+] libfoo.so detectada en la memoria.");
                
                var goodbye_ptr = Module.findExportByName("libfoo.so", "goodbye");
                
                // Comprobamos que goodbye exista para evitar errores
                if (goodbye_ptr) {
                        try {
                                Memory.protect(goodbye_ptr, 1, 'rwx');
                                goodbye_ptr.writeU8(0xc3); // Escribimos la orden de retorno (RET)
                                console.log("[*] Intento de cierre nativo bloqueado (goodbye parcheado con RET).");
                        } catch (e) {
                                console.log("[-] Error parcheando la memoria: " + e);
                        }
                }
        }
}, 5);

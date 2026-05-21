// Programa en JavaScript para bypassear el exit al detectar root
Java.perform(function () {

	// Enlazamos con el System de Android
    	var System = Java.use('java.lang.System');
	
	// Evitamos el cierre de la aplicación
    	System.exit.implementation = function (code) {
        	console.log("[+] Intento de cierre bloqueado.");
    	};
});

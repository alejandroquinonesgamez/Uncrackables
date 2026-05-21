// Programa en JavaScript para bypassear el exit al detectar root y obtener la clave al compararla con la que le introduzcamos
Java.perform(function () {

	// Enlazamos con el System de Android
    	var System = Java.use('java.lang.System');
	
	// Evitamos el cierre de la aplicación
    	System.exit.implementation = function (code) {
        	console.log("[+] Intento de cierre bloqueado.");
    	};
	
	// Prparamos la extracción
    	var aesDecrypt = Java.use('sg.vantagepoint.a.a');
	
	// Ejecutamos la función de desencriptaido
    	aesDecrypt.a.implementation = function (key, encrypted) {
	
		// Guardamos el resultado del desencriptado en result
        	var result = this.a(key, encrypted);
		
		// Traducimos de Bytes a Texto
        	var secret = "";
        	for (var i = 0; i < result.length; i++) {
            		secret += String.fromCharCode(result[i]);
        	}
        	console.log("[!] LA CLAVE SECRETA ES: " + secret);
	
	// Devolvemos el resultado para que continue la ejecución normal
        return result;
    	};
});

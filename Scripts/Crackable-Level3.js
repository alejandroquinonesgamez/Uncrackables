// Programa en JavaScript para bypassear el exit al detectar root
Java.perform(function(){
    	// Bypasseamos los checks de Root en Java
    	let RootDetection = Java.use("sg.vantagepoint.util.RootDetection");
    	RootDetection.checkRoot1.implementation = function(){
        	console.log("[+] Bypass Root 1");
        	return false;
    	}
    	RootDetection.checkRoot2.implementation = function(){
        	console.log("[+] Bypass Root 2");
        	return false;
    	}
    	RootDetection.checkRoot3.implementation = function(){
        	console.log("[+] Bypass Root 3");
        	return false;
    	}

    	// Bloqueamos el cierre desde Java
    	var System = Java.use('java.lang.System');
    	System.exit.implementation = function(code){
    	    	console.log("[+] System.exit bloqueado");
    	};
});

// Bloqueamos el cierre nativo (raise y exit)
// Usamos punteros directos sin funciones complejas para evitar el TypeError
var raise_ptr = Module.findExportByName(null, "raise");
if (raise_ptr) {
    	Interceptor.replace(raise_ptr, new NativeCallback(function (sig) {
        	console.log("[*] Se ha evitado el suicidio nativo (raise)");
        	return 0;
    	}, 'int', ['int']));
}

var exit_ptr = Module.findExportByName(null, "_exit");
if (exit_ptr) {
    	Interceptor.replace(exit_ptr, new NativeCallback(function (status) {
        	console.log("[*] Se ha evitado el suicidio nativo (_exit)");
    	}, 'void', ['int']));
}

// Para la clave: como strncpy te da error, vamos a usar un buscador de memoria
// Este script no hará nada hasta que tú metas la clave en el móvil
console.log("[*] Todo listo. Ignora los avisos de Frida detectado y dale a OK en el móvil.");

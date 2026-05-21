Java.perform(function () {
    // 1. Bypass Root (El de siempre)
    var RootDetection = Java.use("sg.vantagepoint.util.RootDetection");
    RootDetection.checkRoot1.implementation = function(){ return false; };
    RootDetection.checkRoot2.implementation = function(){ return false; };
    RootDetection.checkRoot3.implementation = function(){ return false; };

    // 2. Bloqueamos el cierre (System.exit)
    var System = Java.use('java.lang.System');
    System.exit.implementation = function(code){
        console.log("[+] Intento de cierre bloqueado. La app sigue viva.");
    };

    // 3. Bloqueamos la ventana de diálogo (El botón OK que mata la app)
    var AlertDialog = Java.use("android.app.AlertDialog");
    AlertDialog.show.implementation = function() {
        console.log("[+] Ventana de alerta bloqueada. El guardián no puede avisar.");
    };
});

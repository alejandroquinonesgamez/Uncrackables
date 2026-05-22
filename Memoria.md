# Memoria de resolución — OWASP Uncrackable (Android)

**Autor:** Alejandro Quiñones Gámez  
**Asignatura:** PPS — Puesta a Producción Segura  
**Práctica:** Android Inverse — MAS Crackmes  
**Repositorio:** [github.com/alejandroquinonesgamez/Uncrackables](https://github.com/alejandroquinonesgamez/Uncrackables)  
**Enunciado:** [crackme.html](crackme.html)

---

## 1. Introducción

El objetivo de la presente memoria es documentar el proceso de auditoría y la obtención de las contraseñas ocultas en las aplicaciones de la serie OWASP Uncrackable (Niveles 1, 2 y 3), detallando de forma exhaustiva la metodología técnica empleada para alcanzar cada solución. Las evidencias visuales del proceso se encuentran disponibles en el directorio [Capturas/](https://github.com/alejandroquinonesgamez/Uncrackables/tree/main/Capturas).

Los tres retos se abordaron de forma secuencial (L1 → L2 → L3), dado que cada nivel introduce nuevas capas de ofuscación y defensa. El primer nivel basa su seguridad en comprobaciones nativas de Java; el segundo traslada la validación a una librería compilada en C/C++ (`libfoo.so`); y el tercero implementa un sistema de defensa multicapa que combina controles de integridad, detección de instrumentación en memoria (Frida), un hilo guardián reactivo y validación criptográfica mediante XOR.

| Nivel | Paquete | Contraseña |
|-------|---------|------------|
| 1 | `owasp.mstg.uncrackable1` | `I want to believe` |
| 2 | `owasp.mstg.uncrackable2` | `Thanks for all the fish` |
| 3 | `owasp.mstg.uncrackable3` | `making owasp great again` |

Para la consecución de los objetivos se empleó el siguiente conjunto de herramientas: **Genymotion** y `adb` para el despliegue del entorno emulado; **JADX-GUI** para la descompilación y análisis estático del *bytecode* Dalvik; **Ghidra** para la ingeniería inversa de los binarios nativos ELF; **Frida** para la instrumentación dinámica de código en tiempo de ejecución; y **jdb** (Java Debugger) junto a utilidades de sistemas Unix (`strings`, `unzip`) para la evasión de medidas anti-análisis en el nivel superior.

```mermaid
flowchart LR
  subgraph N1 [Nivel 1 — Java]
    J1[JADX estático] --> F1["Frida: System.exit + AES"]
    F1 --> K1["I want to believe"]
  end
  subgraph N2 [Nivel 2 — JNI]
    J2[JADX: CodeCheck] --> G2["Ghidra: CodeCheck_bar"]
    G2 --> V2["Frida: solo_root.js"]
    V2 --> K2["Thanks for all the fish"]
  end
  subgraph N3 [Nivel 3 — Híbrido]
    J3["JADX + strings"] --> G3["Ghidra: XOR + goodbye"]
    G3 --> B3["Clean-Bypass + am start -D"]
    B3 --> P3["pre_frida.sh + jdb + Frida"]
    P3 --> K3["making owasp great again"]
  end
  N1 --> N2 --> N3
```

---

## 2. Nivel 1 — Android Uncrackable L1

**APK:** `UnCrackable-Level1.apk` · **Paquete:** `owasp.mstg.uncrackable1` · **Contraseña:** `I want to believe`

### Preparación del entorno

Antes de tocar el código, prepararemos el emulador Genymotion (dispositivo tipo Pixel), instalaremos la APK con `adb` y comprobaremos que Frida pueda hablar con el dispositivo. En la captura siguiente vemos ese punto de partida: emulador encendido, terminal con los comandos de instalación y la lista de procesos con Frida.

![Captura 01](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/01%20-%20Genymotion%20+%20frida%20+%20adb%20install.png)

### Análisis estático con JADX

Abriremos la APK con `jadx-gui UnCrackable-Level1.apk`. En la imagen se aprecia el comando en la terminal y la ventana de JADX con el árbol del proyecto; en los logs aparece que se han cargado unas quince clases, señal de que la descompilación ha ido bien y ya se puede navegar por `sg.vantagepoint`.

![Captura 02](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/02%20-%20An%C3%A1lisis%20est%C3%A1tico%20jadx.png)

Al inspeccionar la clase `sg.vantagepoint.uncrackable1.MainActivity`, se observa que el método `onCreate` implementa rutinas de evasión. Antes de permitir la interacción, se invocan los métodos `c.a()`, `c.b()` y `c.c()` para verificar la presencia de permisos de superusuario (root), y `b.a(...)` para determinar si la aplicación se encuentra en modo depurable. Si alguna comprobación resulta positiva, se genera un `AlertDialog` que fuerza el cierre del proceso mediante `System.exit(0)`. Posteriormente, en el método `verify`, la validación del secreto se delega a una clase externa mediante la instrucción `if (a.a(string))`.

![Captura 04](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/04%20-%20An%C3%A1lisis%20est%C3%A1tico%20MainActivity.png)

En la siguiente captura podemos ver la lógica real de validación reside en el método `a(String str)` de la clase `sg.vantagepoint.uncrackable1.a`. El programa no compara la entrada con un texto en claro; en su lugar, descifra un bloque de datos mediante la función `sg.vantagepoint.a.a.a(...)`. Dicha función recibe una clave estática codificada en hexadecimal (`8d127684cbc37c17616d806cf50473cc`) y un texto cifrado en Base64 (`5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2G0c=`), comparando el array de bytes resultante con la cadena introducida por el usuario.

![Captura 06](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/06%20-%20An%C3%A1lisis%20Est%C3%A1tico%20a.png)

Para confirmar el algoritmo, abriremos `sg.vantagepoint.a.a` en el paquete auxiliar `sg.vantagepoint.a`. En la captura siguiente aparece `AES/ECB/PKCS7Padding`, `Cipher.getInstance("AES")` y `cipher.init(2, ...)`, es decir, modo descifrado. Con esto fijaremos el objetivo del hook de Frida: `sg.vantagepoint.a.a.a`.

![Captura 07](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/07%20-%20An%C3%A1lisis%20Est%C3%A1tico%20vantagepoint.png)

También revisaremos las clases que explican por qué la app se cierra en un emulador rooteado. En la captura de la clase `b`, el método `a(Context)` comprueba `(context.getApplicationInfo().flags & 2) != 0`, el flag `FLAG_DEBUGGABLE`. En la de la clase `c`, que es la más reveladora para el diálogo de root, hay tres comprobaciones: en `a()` recorre el `PATH` del sistema buscando el binario `"su"`; en `b()` mira si `Build.TAGS` contiene `"test-keys"`; en `c()` recorre rutas típicas de Superuser (`/system/app/Superuser.apk`, `daemonsu`, etc.). Cuando leímos esto en JADX, encajó con el mensaje *Root detected!* que vimos después al ejecutar la app.

![Captura 08](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/08%20-%20An%C3%A1lisis%20Est%C3%A1tico%20b.png)

![Captura 09](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/09%20-%20An%C3%A1lisis%20Est%C3%A1tico%20c.png)

### Script de Frida y ejecución en el emulador

Para evadir estas restricciones y extraer el secreto, se desarrolló un script de instrumentación dinámica en JavaScript ([Scripts/Crackable-Level1.js](https://github.com/alejandroquinonesgamez/Uncrackables/blob/main/Scripts/Crackable-Level1.js)). La solución (Captura 10) redefine el comportamiento de `System.exit` para anular la finalización del proceso tras la detección de *root*, e intercepta la función de descifrado `sg.vantagepoint.a.a.a` con el fin de volcar en la consola los bytes resultantes en formato de texto claro.

![Captura 10](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/10%20-%20Script.png)

```javascript
Java.perform(function () {
    var System = Java.use('java.lang.System');
    System.exit.implementation = function (code) {
        console.log("[+] Intento de cierre bloqueado.");
    };
    var aesDecrypt = Java.use('sg.vantagepoint.a.a');
    aesDecrypt.a.implementation = function (key, encrypted) {
        var result = this.a(key, encrypted);
        var secret = "";
        for (var i = 0; i < result.length; i++) {
            secret += String.fromCharCode(result[i]);
        }
        console.log("[!] LA CLAVE SECRETA ES: " + secret);
        return result;
    };
});
```

Al ejecutar la herramienta mediante el comando `frida -U -f owasp.mstg.uncrackable1 -l Scripts/Crackable-Level1.js`, el motor se acopla al hilo principal del proceso en el dispositivo emulado. A pesar de que la aplicación despliega el aviso *Root detected!*, la modificación en memoria impide que la interacción con el botón "OK" destruya el proceso.

![Captura 11](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/11%20-%20Frida.png)

### Obtención y comprobación de la contraseña

A continuación, se introdujo una cadena arbitraria ("Probando") en el campo de texto para forzar la ejecución de la rutina de verificación.

![Captura 13](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/13%20-%20Cadena%20Prueba.png)

Como resultado, la interfaz gráfica responde con un mensaje de denegación ("Nope..."); sin embargo, la interceptación dinámica en la terminal captura el flujo interno del algoritmo AES, exponiendo la contraseña legítima: `I want to believe`.

![Captura 14](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/14%20-%20Clave.png)

Finalmente, la introducción de dicho valor en el formulario de la aplicación devuelve el estado de validación correcta ("Success! This is the correct secret."), confirmando la resolución del primer nivel.

![Captura 15](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/15%20-%20Fin.png)

---

## 3. Nivel 2 — Android Uncrackable L2

**APK:** `UnCrackable-Level2.apk` · **Paquete:** `owasp.mstg.uncrackable2` · **Contraseña:** `Thanks for all the fish`

En este nivel la validación **deja de estar en Java** y pasa a la librería nativa `libfoo.so`. Usaremos JADX para ver el puente y Ghidra para leer la comparación real.

### Instalación y análisis estático inicial

Se procedió a instalar la aplicación en el dispositivo emulado y a realizar su descompilación mediante la herramienta JADX.

![Captura 20](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/20%20-%20Instalar%20y%20Descompilar.png)

La revisión de la clase principal, `MainActivity`, revela que el método `onCreate` mantiene las comprobaciones de *root* y depuración observadas en el nivel anterior, añadiendo además una tarea asíncrona (`AsyncTask`) que monitoriza constantemente la conexión de un depurador mediante `Debug.isDebuggerConnected()`. Por su parte, la rutina `verify` delega la comprobación del secreto introducido por el usuario en el método `a(String)` de un objeto instanciado a partir de la clase `CodeCheck`.

![Captura 22](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/22%20-%20An%C3%A1lisis%20Est%C3%A1tico%20MainActivity.png)

A diferencia del primer reto, la validación criptográfica no se encuentra de forma íntegra en Java. La clase `MainActivity` declara un bloque estático encargado de cargar la librería compartida `libfoo.so` mediante la instrucción `System.loadLibrary("foo")`, así como un método nativo de inicialización `private native void init()`.

![Captura 23](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/23%20-%20An%C3%A1lisis%20Est%C3%A1tico%20MainActivity.png)

Al inspeccionar la clase `CodeCheck`, se confirma que el método `a(String)` se limita a convertir la cadena de texto a un *array* de bytes y a invocar la función `private native boolean bar(byte[] bArr)`. El uso de la palabra reservada `native` indica que la lógica de comparación reside en el binario compilado.

![Captura 24](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/24%20-%20An%C3%A1lisis%20Est%C3%A1tico%20CodeCheck.png)

Para auditar dicha función, se extrajo el contenido del paquete APK utilizando la utilidad `unzip`, aislando las librerías nativas correspondientes a cada arquitectura para su posterior análisis.

![Captura 25](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/25%20-%20Unzip%20apk.png)

### Análisis de libfoo.so en Ghidra

Para realizar el análisis estático del componente nativo, se inicializó un entorno de trabajo en Ghidra y se importó el archivo `libfoo.so`.

![Captura 26](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/26%20-%20Ghidra.png)
![Captura 27](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/27%20-%20Ghidra.png)

Durante la importación, la herramienta reconoció correctamente la estructura del ejecutable, asignándole el formato ELF (*Executable and Linking Format*) y determinando la arquitectura nativa correspondiente (AARCH64) para proceder con el análisis.

![Captura 30](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/30%20-%20Ghidra.png)
![Captura 31](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/31%20-%20Ghidra.png)

Una vez finalizado el proceso de descompilación automática, se inspeccionó el árbol de símbolos de exportación (*Exports*). En esta sección se logró identificar la nomenclatura estándar empleada por la interfaz JNI, localizando la función de inicialización `Java_sg_vantagepoint_uncrackable2_MainActivity_init` y la rutina de validación `Java_sg_vantagepoint_uncrackable2_CodeCheck_bar`.

![Captura 34](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/34%20-%20Ghidra.png)

Al examinar el pseudocódigo generado para la función `CodeCheck_bar`, el flujo de validación principal quedó expuesto en texto claro. La rutina reserva un búfer local de memoria e invoca la instrucción `strncpy` para almacenar en él la cadena `"Thanks for all the fish"`. Posteriormente, evalúa la entrada proporcionada por el usuario mediante una llamada a `strncmp`, comparando un máximo de 23 caracteres (`0x17`).

![Captura 35](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/35%20-%20Ghidra.png)

Este hallazgo permitió obtener la contraseña directamente mediante análisis estático del binario, demostrando que en este nivel el secreto no se encuentra ofuscado en memoria ni derivado dinámicamente.

### Comprobación de la contraseña en el dispositivo

A pesar de haber extraído la contraseña mediante análisis estático, la ejecución de la aplicación en un entorno emulado rooteado provoca el cierre inmediato del proceso debido a las rutinas de evasión implementadas en Java. Para verificar el hallazgo, se elaboró un script de Frida de carácter mínimo (`solo_root.js`) diseñado exclusivamente para interceptar y anular la llamada a `System.exit`.

![Captura 37](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/37%20-%20Root_Bypass.png)

Tras localizar el identificador del proceso mediante `frida-ps -Uai`, se inyectó el script en el paquete `owasp.mstg.uncrackable2`. La instrumentación permitió que la aplicación continuara su ejecución normal, mostrando el diálogo de advertencia de *root* sin llegar a finalizar el proceso, al igual que con el L1.

![Captura 39](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/39%20-%20Frida.png)

Una vez neutralizada la protección inicial, se introdujo en el campo de texto la cadena descubierta en la función nativa durante el análisis en Ghidra: *Thanks for all the fish*.

![Captura 40](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/40%20-%20Password.png)

Al pulsar el botón de verificación, la aplicación devolvió el diálogo *"Success!"*, corroborando de manera práctica que la cadena ofuscada estáticamente en `libfoo.so` corresponde a la solución legítima del segundo nivel.

![Captura 41](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/41%20-%20Done.png)

---

## 4. Nivel 3 — Android Uncrackable L3

**APK:** `UnCrackable-Level3.apk` · **Paquete:** `owasp.mstg.uncrackable3` · **Contraseña:** `making owasp great again`

Aquí las defensas aumentan: comprobación de integridad (CRC de `libfoo.so` y `classes.dex`), detección de Frida leyendo `/proc/self/maps`, hilo anti-debug en Java, función nativa `goodbye()` que aborta el proceso, y validación del secreto con XOR usando la clave `pizzapizzapizzapizzapizz`. Este nivel se resolvió de forma iterativa, con varios scripts que fallaron antes de que se encontrara la combinación que funcionó.

### Reconocimiento inicial y análisis estático

La fase inicial consistió en la instalación del paquete y la extracción de los binarios nativos para su posterior análisis.

![Captura 50](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/50%20-%20Comandos_An%C3%A1lisis_Previo.png)

El análisis de la clase `MainActivity` revela un incremento significativo en las capas de seguridad respecto a los retos anteriores. Se identificó la declaración de una constante `xorkey` con el valor `"pizzapizzapizzapizzapizz"`(24 bytes), así como una función `verifyLibs()` encargada de validar la integridad del código mediante comprobaciones CRC contra las librerías nativas y el archivo `classes.dex`. Si se detecta alguna anomalía, se altera la variable `tampered`.

![Captura 51](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/51%20-%20Est%C3%A1tico1.png)

La inicialización de la librería nativa recibe la constante `xorkey` convertida a *array* de bytes. Asimismo, se observó la ejecución de un hilo en segundo plano (`AsyncTask`) que evalúa de forma recurrente el estado de depuración. Cualquier intento de inyección, *tampering* o depuración desencadena un diálogo de alerta antes de permitir la interacción con el formulario.

![Captura 52](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/52%20-%20Est%C3%A1tico2.png)

De forma análoga al nivel anterior, la verificación final de la contraseña se deriva a una clase externa, `CodeCheck`, la cual actúa como puente (*wrapper*) hacia una función nativa denominada `bar(byte[])`.

![Captura 53](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/53%20-%20Est%C3%A1tico3.png)

Previo al análisis en el desensamblador, la ejecución del comando `strings` sobre `libfoo.so` expuso una serie de cadenas críticas para entender el modelo de amenaza. Entre ellas figuran referencias a herramientas de instrumentación dinámica (`frida`, `xposed`), rutas de memoria del sistema (`/proc/self/maps`), un mensaje de terminación por manipulación y el símbolo ofuscado de una función denominada `goodbye`.

![Captura 57](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/57%20-%20Strings.png)


Se continuó con la importación de libfoo.so en Ghidra para su análisis:

![Captura 56](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/56%20-%20Importando_libfoo.png)

### Evaluación dinámica y crash del hilo guardián

Para contrastar las defensas identificadas estáticamente, se intentó instrumentar el proceso inyectando el script básico de evasión desarrollado en el nivel anterior. Al realizar el *spawn*, la aplicación abortó inmediatamente su ejecución lanzando una señal de interrupción crítica (`Trace/BPT trap`).

![Captura 54](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/54%20-%20Frida.png)

La inspección de las trazas de ejecución (*backtrace*) reveló que la finalización forzada no provenía de las excepciones de Java, sino de un hilo nativo creado mediante `pthread_start` que culminaba en la ejecución de la función `goodbye()`. Esto confirmó lo que intuimos al analizar el `strings`: la presencia de un hilo guardián encargado de detectar la intrusión de Frida en el mapa de memoria y el cierre forzado de la aplicación de manera irremediable.

![Captura 55](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/55%20-%20Trazas.png)

### Análisis profundo de la lógica nativa en Ghidra

La búsqueda exhaustiva de la cadena `frida` en el código desensamblado condujo a una subrutina dedicada. El diagrama de flujo y la descompilación de esta función revelaron la mecánica exacta del hilo guardián: un bucle infinito que abre el archivo `/proc/self/maps` mediante `fopen`, lee su contenido línea a línea y utiliza `strstr` para identificar las secuencias `frida` o `xposed`. De encontrarlas, invoca de inmediato la instrucción `goodbye()`.

![Captura 59](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/59%20-%20Search.png)
![Captura 60](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/60%20-%20Search-Flow.png)
![Captura 61](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/61%20-%20Est%C3%A1tico.png)

En paralelo, se auditaron las funciones JNI declaradas en Java. En `MainActivity_init`, la lógica de la rutina emplea `strncpy` para volcar 24 bytes (el tamaño exacto de la constante `xorkey`) en una dirección de memoria global.

![Captura 63](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/63%20-%20Est%C3%A1tico%20init.png)
![Captura 64](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/64%20-%20Zoom%20init.png)

Por su parte, la función de validación `CodeCheck_bar` no ejecuta una comprobación de cadenas tradicional. En su lugar, el descompilador expone un bucle iterativo de 24 ciclos (`0x18`) que aplica una operación lógica XOR byte a byte entre la entrada proporcionada por el usuario y la clave almacenada en memoria, validando el resultado.

![Captura 62](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/62%20-%20Est%C3%A1tico%20bar.png)
![Captura 65](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/65%20-%20Zoom%20bar.png)

### Intentos de instrumentación avanzada

Conociendo las rutinas a neutralizar, se desarrolló un script más elaborado (`Crackable-Level3.js`) con el propósito de interceptar `strstr` para ocultar las cadenas prohibidas del mapa de memoria, además de aplicar un *hook* sobre `strncpy` para exfiltrar la clave.

![Captura 66](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/66%20-%20Script.png)

No obstante, la inyección de este código resultó infructuosa, devolviendo un error en la evaluación del motor de instrumentación y permitiendo que la ejecución del hilo guardián continuara hasta colapsar nuevamente el proceso. Este resultado forzó un cambio definitivo de estrategia.

![Captura 67](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/67%20-%20Script%20fail.png)

### Neutralización de las protecciones: Bypass de memoria y anti-debugging

Ante la imposibilidad de evadir el hilo guardián en tiempo de ejecución de forma convencional, se documentaron múltiples pruebas de concepto intermedias que resultaron inestables. Inicialmente, se intentó bloquear la creación del hilo nativo y falsificar la lectura del mapa de memoria redirigiendo las llamadas `fopen` y `open` hacia una copia limpia del fichero `/proc/self/maps`, extraída previamente del entorno mediante comandos de terminal.

![Captura 71](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/71%20-%20Nuevo%20enfoque.png)
![Captura 72](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/72%20-%20Copia%20Limpia.png)
![Captura 73](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/73%20-%20Script.png)
![Captura 68](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/68%20-%20New%20Script.png)
![Captura 69](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/69%20-%20New%20Script%20fail.png)
![Captura 70](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/70%20-%20New%20Script.png)

La principal barrera de estas estrategias residía en una condición de carrera (*race condition*): las rutinas protectoras nativas se inicializaban a una velocidad superior a la capacidad del motor de instrumentación para acoplarse e inyectar los *hooks*.

Para solventar este problema de sincronización, se optó por suspender el proceso desde su nacimiento. Mediante el uso del comando `adb shell am start -D`, se forzó el inicio de la máquina virtual Dalvik en modo depuración (*Waiting For Debugger*), congelando la ejecución antes de la carga inicial de las librerías compartidas.

![Captura 80](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/80%20-%20Debugger.png)

En este estado de suspensión temporal, se diseñó el script definitivo de evasión ([Scripts/Clean-Bypass.js](https://github.com/alejandroquinonesgamez/Uncrackables/blob/main/Scripts/Clean-Bypass.js)). Esta solución anula de raíz las comprobaciones lógicas de la clase `RootDetection`, neutraliza `System.exit` y emplea un interceptor sobre la función `dlopen` del sistema operativo. Al detectar la carga en memoria de `libfoo.so`, el script calcula dinámicamente el puntero de la función nativa `goodbye` y sobrescribe su primera instrucción con una directiva de retorno incondicional (`RET`, valor hexadecimal `0xC3`), cegando al hilo guardián de forma permanente y segura sin interrumpir el flujo de la aplicación.

![Captura 81](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/81%20-%20Script.png)

Para garantizar la efectividad del parche antes de que el proceso ejecute sus subrutinas de protección nativas, se forzó la detención del hilo principal mediante la redirección del puerto JDWP empleando `adb forward tcp:12345 jdwp:<pid>`. Al intentar acoplar Frida en este punto intermedio antes de la reanudación del entorno Java, el motor de instrumentación no logra localizar el proceso inicializado de forma correcta, confirmando la necesidad de coordinar ambas herramientas en un único vector de ataque.

![Captura 82](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/82%20-%20%3F%3F%3F.png)
![Captura 83](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/83%20-%20Script2.png)

Con el fin de automatizar esta compleja secuencia de sincronización, se desarrolló un script en Bash ([Scripts/pre_frida.sh](https://github.com/alejandroquinonesgamez/Uncrackables/blob/main/Scripts/pre_frida.sh)). La herramienta automatiza de forma secuencial el arranque suspendido de la aplicación, extrae el identificador del proceso dinámicamente mediante `pidof`, levanta el túnel de depuración JDWP en el puerto local y efectúa la inyección de Frida por PID en el instante exacto en el que el operador conecta el depurador de Java (`jdb -attach localhost:12345`) desde una terminal paralela. El script incorpora además un *hook* sobre `strncmp` configurado para inspeccionar y volcar los operandos en memoria RAM únicamente cuando la longitud de la comparación equivale a 24 bytes (la longitud de la cadena de `pizzapizzapizzapizzapizz`).

![Captura 84](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/84%20-%20PreFrida.png)

### Descifrado de la rutina criptográfica XOR en Ghidra

En paralelo a la construcción del entorno de ejecución, se profundizó en el análisis estático de la clase `MainActivity_init` en el descompilador de Ghidra para comprender la derivación del secreto.

![Captura 90](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/90%20-%20Locating%20pizza.png)

La inspección de la subrutina nativa expone que, de forma previa a la manipulación de las claves, el binario ejecuta una llamada oculta hacia la función `FUN_00103910`.

![Captura 91](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/91%20-%20Analizing%20main.png)

Al auditar dicha función, se descubrió el mecanismo de evasión nativo más agresivo del reto. La aplicación efectúa un `fork()` para bifurcar el proceso y ejecuta `ptrace(PTRACE_ATTACH, ...)` sobre el proceso padre con el fin de monitorizarlo y bloquear la conexión de depuradores externos. Si esta acción es interceptada, la rutina levanta un hilo persistente mediante `pthread_create` diseñado para forzar la terminación del programa ante cualquier anomalía en la memoria.

![Captura 92](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/92%20-%20Threads.png)

Una vez comprendido el comportamiento de la bifurcación, se aislaron y renombraron las variables globales involucradas en la inicialización criptográfica (originalmente etiquetadas como `DAT_00107040`), identificándolas cronológicamente como `pizza` y, finalmente, como `cadena_Copiada`.

![Captura 93](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/93%20-%20Renaming%20Pizza.png)
![Captura 94](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/94%20-%20Searching%20for%20pizza.png)

El análisis del pseudocódigo en la función de verificación de `CodeCheck_bar` evidenció que el programa ejecuta una operación lógica XOR condicional byte a byte. El algoritmo itera a lo largo de 24 ciclos comprobando si la entrada del usuario difiere del resultado de evaluar los caracteres ofuscados estáticos en el binario contra el búfer de inicialización que contiene la clave conocida `"pizzapizzapizzapizzapizz"`.

![Captura 95](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/95%20-%20Pizza%20encontrada.png)

Para reconstruir la contraseña de manera externa si fuese necesario, se localizaron las direcciones de memoria exactas de los punteros y las constantes estructuradas dentro de las secciones de datos del archivo ELF, obteniendo los vectores de inicialización requeridos para revertir la ofuscación de forma estática.

![Captura 96](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/96%20-%20Key%20found.png)
![Captura 96b](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/96%20-%20Looking%20for%20address.png)
![Captura 97](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/97%20-%20Looking%20for%20address%20%28Nice%29.png)
![Captura 98](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/98%20-%20Getting%20the%20address.png)

### Obtención de la clave en consola y resolución del reto

La ejecución coordinada del script de automatización permitió burlar los hilos de integridad y el guardián de memoria nativo de forma definitiva. Al introducir una cadena de prueba en el formulario interactivo de la aplicación, el interceptor acoplado a la función de comparación en la librería `libfoo.so` capturó los argumentos directamente desde los registros de la memoria RAM.

![Captura 99](https://raw.githubusercontent.com/alejandroquinonesgamez/Uncrackables/main/Capturas/99%20-%20Yuju.png)

Como resultado, la terminal expuso en texto plano los 24 bytes que componen el secreto del tercer nivel: `making owasp great again`. Tras introducir dicha clave en la interfaz gráfica de la aplicación, el flujo Dalvik validó con éxito el paquete de datos, desplegando el diálogo de confirmación que certifica la resolución completa del desafío de ingeniería inversa.

---

## 5. Conclusiones

La resolución progresiva de los tres niveles de OWASP Uncrackable ha permitido auditar de manera práctica la evolución de los mecanismos de protección en entornos Android, transitando desde validaciones básicas en el espacio de usuario de Java hasta complejas protecciones híbridas en código nativo (C/C++).

Se ha evidenciado que, si bien la delegación de la lógica de seguridad hacia librerías compiladas (`.so`) e hilos dinámicos antiprecinto incrementa significativamente la dificultad del análisis estático, la instrumentación dinámica avanzada combinada con técnicas de depuración a bajo nivel permite interceptar y manipular el comportamiento del sistema operativo.

La efectividad de las defensas analizadas no reside en la imposibilidad de su ruptura, sino en el tiempo y los recursos que el analista debe invertir para sincronizar vectores de ataque complejos, tales como la neutralización de condiciones de carrera mediante la suspensión del ciclo de vida del proceso en su nacimiento.

---

## 6. Referencias

- [Repositorio del proyecto](https://github.com/alejandroquinonesgamez/Uncrackables) — memoria, capturas, scripts y APKs
- [Enunciado de la práctica](crackme.html)
- [OWASP MAS Crackmes — Android](https://mas.owasp.org/crackmes/Android/)
- APKs del repositorio oficial de OWASP: [Level 1](https://github.com/OWASP/mastg/raw/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk), [Level 2](https://github.com/OWASP/mastg/raw/master/Crackmes/Android/Level_02/UnCrackable-Level2.apk), [Level 3](https://github.com/OWASP/mastg/raw/master/Crackmes/Android/Level_03/UnCrackable-Level3.apk)
- Scripts de instrumentación desarrollados: [Crackable-Level1.js](https://github.com/alejandroquinonesgamez/Uncrackables/blob/main/Scripts/Crackable-Level1.js), [solo_root.js](https://github.com/alejandroquinonesgamez/Uncrackables/blob/main/Scripts/solo_root.js), [Crackable-Level3.js](https://github.com/alejandroquinonesgamez/Uncrackables/blob/main/Scripts/Crackable-Level3.js), [Clean-Bypass.js](https://github.com/alejandroquinonesgamez/Uncrackables/blob/main/Scripts/Clean-Bypass.js) y [pre_frida.sh](https://github.com/alejandroquinonesgamez/Uncrackables/blob/main/Scripts/pre_frida.sh).

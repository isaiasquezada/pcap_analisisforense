# pcap_analisisforense
Script desarrollado para analizar archivos PCAP usando .Net Core y Kaitai

El script se lo ha creado en C#, usando las librerías de .Net Core y Kaitai, el cual contiene múltiples funciones para el análisis de redes; y por consiguiente archivos PCAP.

Comando: dotnet ParsePCAP.dll [ruta=archivo.pcap] [filtro=condicion1,condicion2] [decode=si/no]

Ejemplo: dotnet ParsePCAP.dll /ruta/archivo.pcap HTTP,microsoft,GET si

Donde filtros son las cadenas de texto que se buscan en cada uno de los paquetes analizados; además para este caso se incluye la opción de decodificar de base64 a texto para ver el contenido enviado a través del método GET.

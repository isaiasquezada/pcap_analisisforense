using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace Kaitai
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("\nScript para parsear PCAP. Módulo: Análisis Forense\n\nComando: dotnet ParsePCAP.dll [ruta=archivo.pcap] [filtro=condicion1,condicion2] [decode=si/no]");
                Console.WriteLine("\nEjemplo: dotnet ParsePCAP.dll /ruta/archivo.pcap HTTP,microsoft,GET si\n");
            }
            else
            {
                //Cargar archivo PCAP
                var data = Pcap.FromFile(args[0]);
                //Pasar condiciones a array
                string[] split = args[1].Split(',');
                //Buscar cada uno de los paquetes
                foreach (Kaitai.Pcap.Packet paquete in data.Packets)
                {
                    byte[] result = ObjectToByteArray(paquete.Body);
                    string content = System.Text.Encoding.UTF8.GetString(result);
                    int c = 0;
                    foreach (string condicion in split)
                    {
                        if (!content.Contains(condicion)) { c++; }
                    }
                    //Presentar resultados
                    if (c == 0)
                    {
                        Console.WriteLine(content);
                        //Decodificar Base64 si el usuario lo requiere
                        if (args[2].ToLower() == "si")
                        {
                            string contentURL = content.Substring(content.IndexOf("GET ") + 4);
                            contentURL = contentURL.Substring(contentURL.IndexOf("?"));
                            contentURL = contentURL.Substring(1, contentURL.IndexOf(" ")-1);
                            string[] parametros = contentURL.Split('&');
                            Console.WriteLine("\nDecode64:\n");
                            int i = 1;
                            foreach (string param in parametros)
                            {
                                Console.WriteLine("[Parámetro " + i + "] > " + System.Text.ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String(param.Substring(0,40))));
                                i++;
                            }
                        }
                    }
                }
            }
        }

        static byte[] ObjectToByteArray(object obj)
        {
            if (obj == null)
                return null;
            BinaryFormatter bf = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream())
            {
                bf.Serialize(ms, obj);
                return ms.ToArray();
            }
        }
    }
}

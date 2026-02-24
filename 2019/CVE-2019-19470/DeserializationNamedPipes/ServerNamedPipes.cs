using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.Serialization.Formatters.Binary;

namespace ServerNamedPipes
{
    internal class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                using (NamedPipeServerStream server = new NamedPipeServerStream("redteamrd_pipe"))
                {
                    Console.WriteLine("[+] Esperando conexión del cliente en el Named Pipe: redteamrd_pipe...");
                    server.WaitForConnection();
                    Console.WriteLine("[+] Cliente conectado al Named Pipe: redteamrd_pipe");

                    try
                    {
                        using (MemoryStream ms = new MemoryStream())
                        {
                            byte[] buffer = new byte[4096];
                            int bytesRead;

                            // Leer los datos en bloques de 4096 bytes
                            while ((bytesRead = server.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                ms.Write(buffer, 0, bytesRead);

                                // Verificar si no hay más datos disponibles para leer
                                if (!server.IsConnected || server.CanRead == false)
                                    break;
                            }

                            ms.Position = 0; // Resetear la posición al inicio del stream

                            // Deserializar los datos desde el MemoryStream
                            BinaryFormatter formatter = new BinaryFormatter();
                            object deserializedObject = formatter.Deserialize(ms);

                            Console.WriteLine("[+] Objeto deserializado: ");
                            Console.WriteLine(deserializedObject.ToString());
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[!] Error durante la deserialización: " + e.Message);
                    }

                    Console.WriteLine("[+] Conexión cerrada. Esperando nueva conexión...");
                }
            }
        }
    }
}

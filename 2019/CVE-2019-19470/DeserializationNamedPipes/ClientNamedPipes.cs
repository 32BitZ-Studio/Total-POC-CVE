using System;
using System.IO;
using System.IO.Pipes;

namespace ClientNamedPipes
{
    internal class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                try
                {
                    Console.Write("Ingrese la ruta completa del archivo que contiene el string Base64: ");
                    string filePath = Console.ReadLine();

                    if (!File.Exists(filePath))
                    {
                        Console.WriteLine("[!] Archivo no encontrado, por favor ingrese una ruta válida.");
                        continue;
                    }

                    // Leer el string Base64 del archivo
                    string base64String = File.ReadAllText(filePath);

                    if (string.IsNullOrWhiteSpace(base64String))
                    {
                        Console.WriteLine("[!] El archivo está vacío o no contiene datos válidos.");
                        continue;
                    }

                    // Convertir el string Base64 a un array de bytes
                    byte[] data = Convert.FromBase64String(base64String);

                    // Conectar al pipe y enviar los datos
                    using (NamedPipeClientStream client = new NamedPipeClientStream(".", "redteamrd_pipe", PipeDirection.Out))
                    {
                        Console.WriteLine("[+] Conectando al Named Pipe: redteamrd_pipe...");
                        client.Connect();
                        Console.WriteLine("[+] Conectado al Named Pipe: redteamrd_pipe");

                        Console.WriteLine($"[+] Enviando data deserializada desde el archivo: {filePath}");

                        client.Write(data, 0, data.Length);
                        client.Flush();
                    }

                    Console.WriteLine("[+] Data enviada exitosamente.");
                }
                catch (Exception e)
                {
                    Console.WriteLine("[!] Error: " + e.Message);
                }

                Console.WriteLine("[+] Esperando nuevas instrucciones...");
            }
        }
    }
}

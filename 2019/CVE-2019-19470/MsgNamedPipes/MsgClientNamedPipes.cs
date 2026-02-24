using System;
using System.IO.Pipes;
using System.Text;

namespace MsgClientNamedPipes
{
    internal class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                try
                {
                    Console.Write("[+] Ingrese el texto a convertir a mayúsculas: ");
                    string inputText = Console.ReadLine();

                    if (string.IsNullOrWhiteSpace(inputText))
                    {
                        Console.WriteLine("     [!] El texto ingresado está vacío. Por favor, ingrese algo.");
                        continue;
                    }

                    // Convertir el texto a bytes
                    byte[] data = Encoding.UTF8.GetBytes(inputText);

                    // Conectar al pipe y enviar los datos
                    using (NamedPipeClientStream client = new NamedPipeClientStream(".", "redteamrd_pipe", PipeDirection.InOut))
                    {
                        Console.WriteLine("     [+] Conectando al Named Pipe: redteamrd_pipe...");
                        client.Connect();
                        Console.WriteLine("     [+] Conectado al Named Pipe: redteamrd_pipe");

                        // Enviar los datos al servidor
                        client.Write(data, 0, data.Length);
                        client.Flush();

                        // Leer la respuesta del servidor
                        byte[] buffer = new byte[4096];
                        int bytesRead = client.Read(buffer, 0, buffer.Length);

                        string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                        Console.WriteLine($"     [+] Respuesta del servidor: {response}\n");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[!] Error: " + e.Message);
                }
            }
        }
    }
}

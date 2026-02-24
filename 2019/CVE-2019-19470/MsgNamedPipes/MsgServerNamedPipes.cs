using System;
using System.IO.Pipes;
using System.Text;

namespace MsgServerNamedPipes
{
    internal class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                using (NamedPipeServerStream server = new NamedPipeServerStream("redteamrd_pipe", PipeDirection.InOut))
                {
                    Console.WriteLine("[+] Esperando conexión del cliente en el Named Pipe: redteamrd_pipe...");
                    server.WaitForConnection();

                    Console.WriteLine("     [+] Cliente conectado al Named Pipe: redteamrd_pipe");
                    try
                    {
                        // Leer los datos recibidos en un array de bytes
                        byte[] buffer = new byte[4096];
                        int bytesRead = server.Read(buffer, 0, buffer.Length);

                        string receivedText = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                        Console.WriteLine($"     [+] Texto recibido: {receivedText}");

                        // Convertir el texto a mayúsculas
                        string upperText = receivedText.ToUpper();

                        // Enviar el texto convertido de vuelta al cliente
                        byte[] response = Encoding.UTF8.GetBytes(upperText);
                        server.Write(response, 0, response.Length);
                        server.Flush();

                        Console.WriteLine("     [+] Texto convertido a mayúsculas y enviado al cliente.");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("     [!] Error durante el procesamiento: " + e.Message);
                    }

                    Console.WriteLine("\n[-] Conexión cerrada. Esperando nueva conexión...\n");
                }
            }
        }
    }
}

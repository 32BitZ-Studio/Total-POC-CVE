using System;
using System.Diagnostics;

namespace ModificarPEB
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Process currentProcess = Process.GetCurrentProcess();

            // Obtener el nombre del archivo ejecutable del proceso actual
            string imagePathName = currentProcess.MainModule.FileName;

            // Mostrar la ruta completa del ejecutable
            Console.WriteLine($"Executable Path: {imagePathName}");

            string binPath = "C:\\Windows\\System32\\svchost.exe";

            Console.ReadKey();

            if (!Masquerade.SelectedProcess(binPath).Contains("svchost.exe"))
            {
                Console.WriteLine("[-] Masquerading Fail Closing...");
                Console.ReadLine();
                Environment.Exit(0);
            }

            imagePathName = currentProcess.MainModule.FileName;

            // Mostrar la ruta completa del ejecutable
            Console.WriteLine($"\nExecutable Path: {imagePathName}");

            Console.ReadKey();
        }
    }
}

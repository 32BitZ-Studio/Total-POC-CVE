// ----------------------------------------------------
// Programmer       : Ebrahim Shafiei (EbraSha)
// Email            : Prof.Shafiei@Gmail.com
// ----------------------------------------------------

// Disclaimer: This tool is intended solely for demonstrating and validating a newly discovered security vulnerability in AnyDesk.
// Unauthorized or illegal use of this tool is strictly prohibited.

using System;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.RegularExpressions;

class Program
{
    static string targetProcessName = "";

    static async Task Main()
    {
        string banner = @"
###############################################################
#                                                             #
#         Abdal AnyDesk Remote IP Detector                    #
#                                                             #
#      Demonstration tool for security vulnerability testing   #
#             in AnyDesk remote connection                    #
#                                                             #
#       *** Authorized Use Only ***                           #
# ----------------------------------------------------------- #
# Programmer: Ebrahim Shafiei (EbraSha)                       #
# Email     : Prof.Shafiei@Gmail.com                          #
###############################################################
";

        Console.WriteLine(banner);
        Console.WriteLine("Starting target IP monitoring on AnyDesk");
        // Ask user for the process name to filter (optional)
        // Console.Write("Enter the name of the software to filter (leave empty for all): ");
        // targetProcessName = Console.ReadLine()?.Trim();
        targetProcessName = "AnyDesk";

        // Start the monitoring task
        Task monitoringTask = MonitorConnectionsAsync();

        // Keep the application running
        await Task.WhenAll(monitoringTask);
    }

    // Asynchronous method to continuously monitor connections
    static async Task MonitorConnectionsAsync()
    {
        while (true)
        {
            try
            {
                // Display active TCP connections
                await Task.Run(() => ListTcpConnections());

                // Display active UDP listeners
                await Task.Run(() => ListUdpListeners());

                // Wait for a short interval before checking again
                await Task.Delay(5000); // 5 seconds delay
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error occurred: {ex.Message}");
            }
        }
    }

    // Method to list all active TCP connections with associated process names
    static void ListTcpConnections()
    {
        Console.WriteLine("TCP connection detected and examined for target IP leakage.");
        
        IPGlobalProperties ipProperties = IPGlobalProperties.GetIPGlobalProperties();
        TcpConnectionInformation[] tcpConnections = ipProperties.GetActiveTcpConnections();

        foreach (TcpConnectionInformation connection in tcpConnections)
        {
            try
            {
                // Get process ID associated with the connection port
                int processId = GetProcessId(connection.LocalEndPoint.Port);

                // Get process name if available
                string processName = Process.GetProcessById(processId).ProcessName;

                // Check if the process name matches the target process name or display all if target is empty
                 

                if (processName.ToLower() == "anydesk" && connection.RemoteEndPoint.Port != 443 && connection.RemoteEndPoint.Port != 80)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"Process: {processName}");
                    Console.WriteLine($"Local IP: {connection.LocalEndPoint.Address}, Port: {connection.LocalEndPoint.Port}");
                    Console.WriteLine($"Remote IP: {connection.RemoteEndPoint.Address}, Port: {connection.RemoteEndPoint.Port}");
                    Console.WriteLine($"State: {connection.State}");
                    Console.ResetColor();
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.BackgroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Detected Remote Ip : {connection.RemoteEndPoint.Address}");
                    Console.ResetColor();
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("------------------------------");
                    Console.ResetColor();
                    Console.ReadLine();
                }
                else
                {
                    /*
                     Console.WriteLine($"Process: {processName}");
                    Console.WriteLine($"Local IP: {connection.LocalEndPoint.Address}, Port: {connection.LocalEndPoint.Port}");
                    Console.WriteLine($"Remote IP: {connection.RemoteEndPoint.Address}, Port: {connection.RemoteEndPoint.Port}");
                    Console.WriteLine($"State: {connection.State}");
                    Console.WriteLine("------------------------------");
                     */

                }
            }
            catch (Exception ex)
            {
                //Console.WriteLine($"Could not retrieve process name: {ex.Message}");
            }
        }
    }

    // Method to list all UDP listeners
    static void ListUdpListeners()
    {
        Console.WriteLine("UDP connection detected and examined for target IP leakage.");
        IPGlobalProperties ipProperties = IPGlobalProperties.GetIPGlobalProperties();
        IPEndPoint[] udpListeners = ipProperties.GetActiveUdpListeners();

        foreach (IPEndPoint listener in udpListeners)
        {
            try
            {
                // Get process ID associated with the listener port
                int processId = GetProcessId(listener.Port);

                // Get process name if available
                string processName = Process.GetProcessById(processId).ProcessName;

                // Check if the process name matches the target process name or display all if target is empty
                if (string.IsNullOrEmpty(targetProcessName) || processName.Equals(targetProcessName, StringComparison.OrdinalIgnoreCase))
                {
                    if(listener.Port == 7070)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"Process: {processName}");
                        Console.WriteLine($"Local IP: {listener.Address}, Port: {listener.Port}");
                        Console.WriteLine("------------------------------");
                        Console.ResetColor();
                        Console.ReadLine();
                    }
                    else
                    {
                        /*
                          Console.WriteLine($"Process: {processName}");
                         Console.WriteLine($"Local IP: {listener.Address}, Port: {listener.Port}");
                         Console.WriteLine("------------------------------");
                         */
                    }

                }
            }
            catch (Exception ex)
            {
               // Console.WriteLine($"Could not retrieve process name: {ex.Message}");
            }
        }
    }

    // Helper method to get process ID based on port using netstat
    static int GetProcessId(int port)
    {
        try
        {
            // Start the netstat process
            Process netstat = new Process();
            netstat.StartInfo.FileName = "netstat";
            netstat.StartInfo.Arguments = "-a -n -o";
            netstat.StartInfo.UseShellExecute = false;
            netstat.StartInfo.RedirectStandardOutput = true;
            netstat.StartInfo.CreateNoWindow = true;
            netstat.Start();

            // Read the output from netstat
            string output = netstat.StandardOutput.ReadToEnd();
            netstat.WaitForExit();

            // Regular expression to find the process ID associated with the local port
            string pattern = $@"\s+TCP\s+\S+:{port}\s+\S+\s+\S+\s+(\d+)";
            Regex regex = new Regex(pattern);
            Match match = regex.Match(output);

            if (match.Success && int.TryParse(match.Groups[1].Value, out int processId))
            {
                return processId;
            }
            else
            {
                throw new Exception("Process ID not found for the specified port.");
            }
        }
        catch (Exception ex)
        {
           // Console.WriteLine($"Error retrieving process ID: {ex.Message}");
            return -1; // Return -1 if the process ID cannot be found
        }
    }
}

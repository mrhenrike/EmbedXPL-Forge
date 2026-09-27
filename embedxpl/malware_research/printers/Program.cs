using System;
using System.Drawing;
using System.Drawing.Printing;
using System.Runtime.InteropServices;



namespace PrintMalware
{
    internal class Program
    {
        static void Main(string[] args)
        {
            [DllImport("kernel32.dll")]
            static extern IntPtr GetConsoleWindow();

            [DllImport("user32.dll")]
            static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

            const int SW_HIDE = 0;
            const int SW_SHOW = 5;

            var handle = GetConsoleWindow();
            // Check if --hide is present in command line arguments
            bool hideConsole = PrintMalware.Vars.ShouldHideConsole(args);

            // Hide the console window if --hide is present
            if (hideConsole) ShowWindow(handle, SW_HIDE);

            var random = new Random();

            var message = PrintMalware.Vars.printMessages[random.Next(0, PrintMalware.Vars.printMessages.Length)];

            // Get the first printer
            string firstPrinter = GetFirstPrinter();

            if (firstPrinter != null)
            {
                // Print the message on the first printer
                PrintMessage(message, firstPrinter);
                Console.WriteLine($"Message sent to {firstPrinter}.");
            }
            else
            {
                Console.WriteLine("No printers found.");
            }

            // Show the console window before exiting
            if (hideConsole) ShowWindow(handle, SW_SHOW);
        }

        static string GetFirstPrinter()
        {
            foreach (string printer in System.Drawing.Printing.PrinterSettings.InstalledPrinters)
            {
                return printer;
            }
            return null;
        }

        static void PrintMessage(string message, string printerName)
        {
            using (PrintDocument printDocument = new PrintDocument())
            {
                printDocument.PrinterSettings.PrinterName = printerName;
                printDocument.PrintPage += (sender, e) =>
                {
                    e.Graphics.DrawString(message, new Font("Arial", 12), Brushes.Black, 10, 10);
                };

                printDocument.Print();
            }
        }
    }
}

# Print Malware

Print Malware is a playful project that sends friendly cat-themed messages to your printer. It's harmless and designed for fun.

## Usage

To run the Print Malware program, follow these steps:

1. Clone the repository:

   ```bash
    git clone https://github.com/withervt/print-malware.git
   ```

2. Navigate to the project directory:

   ```bash
   cd print-malware
   ```

3. Build and run the program:

   ```bash
   dotnet run
   ```

   <details><summary>More Info</summary>
   If you want to hide the console window, use the --hide argument:

   ```bash
   dotnet run -- --hide
   ```

   </details>

4. Enjoy the surprise messages sent to your printer!


## Customization

Feel free to customize the messages in the [`vars.cs`](https://github.com/withervt/print-malware/blob/main/vars.cs) file in the `PrintMalware` namespace.
using System;

namespace PrintMalware
{
    public static class Vars
    {
        public static string[] printMessages = new string[]
        {
            "Hello, I am a friendly cat girl.\n\n\nThis was sent to your printer from a piece of Malware.\n\n\nTHIS IS HARMLESS!!!\n\n\nMake sure to check me out: https://git.hylia.dev/print-malware",
            "Hewwo, I am a fwiendwy *whispers to self* cat giww.\n\n\nThis was sent t-to youw pwintew fwom a piece ÚwÚ of Mawwawe.\n\n\nTHIS ÚwÚ IS ^w^ HAWMWESS!!!\n\n\nMake suwe t-to check me out: https://git.hylia.dev/print-malware",
            "Greetings! I'm a cheerful kitten who found its way into your printer.\n\n\nNo need to worry, I bring only good vibes and cute meows.\n\n\nCheck me out: https://git.hylia.dev/print-malware",
            "Meowza! You've got a surprise print from your friendly neighborhood malware kitten.\n\n\nJust spreading some purrfection and joy.\n\n\nVisit me at: https://git.hylia.dev/print-malware",
            "Paws and claws! I'm here to remind you that life is better with a touch of mischief.\n\n\nEnjoy this unexpected print brought to you by your mischievous malware companion.\n\n\nFind more fun: https://git.hylia.dev/print-malware"
        };

        public static bool ShouldHideConsole(string[] args)
        {
            return Array.Exists(args, arg => arg.ToLower() == "--hide");
        }
    }
}

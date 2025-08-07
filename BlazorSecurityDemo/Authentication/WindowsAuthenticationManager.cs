using System.Text.RegularExpressions;

namespace BlazorSecurityDemo.Authentication
{
    public partial class WindowsAuthenticationManager : ServerAuthenticationManager
    {
        public override async Task<UserAuthenticationDetails> CheckPasswordAsync(string username, string password)
        {
            using StringWriter sw = new();

            string cmd = "whoami /groups /priv /fo csv";
            var rc = await CommandProcessor.StartCommand(
                cmd,
                userid: username,
                password: password,
                outputTextWriter: sw
                );
            if (rc != 0) return new(username, false, [], []);

            UserAuthenticationDetails result = new(username, true, [], []);
            ProcessWhoamiOutput(result, sw.ToString());

            return result;
        }

        private enum InputState
        {
            RUNNING, READING_GROUPS, READING_PRIVS
        };

        private static void ProcessWhoamiOutput(UserAuthenticationDetails response, string output)
        {
            var pattern = CSVOutput();
            var lines = output.Split("\n");
            var parseState = InputState.RUNNING;
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                switch (parseState)
                {
                    case InputState.RUNNING:
                        if (trimmed.StartsWith("\"Group Name"))
                        {
                            parseState = InputState.READING_GROUPS;
                        }
                        else if (trimmed.StartsWith("\"Privilege Name"))
                        {
                            parseState = InputState.READING_PRIVS;
                        }
                        break;
                    case InputState.READING_GROUPS:
                        if (trimmed == "")
                        {
                            parseState = InputState.RUNNING;
                            break;
                        }

                        Match groupMatch = pattern.Match(trimmed);
                        if (groupMatch.Success)
                            response.Groups.Add(groupMatch.Groups["val"].Value);
                        break;
                    case InputState.READING_PRIVS:
                        if (trimmed == "")
                        {
                            parseState = InputState.RUNNING;
                            break;
                        }

                        Match privsMatch = pattern.Match(trimmed);
                        if (privsMatch.Success)
                        {
                            var name = privsMatch.Groups["val"].Value;
                            privsMatch = privsMatch.NextMatch();
                            privsMatch = privsMatch.NextMatch();
                            var state = privsMatch.Groups["val"].Value;
                            response.Privileges.Add(new(name, state == "Enabled"));
                        }
                        break;
                    default:
                        break;
                }
            }
        }

        [GeneratedRegex(@"
            # Parse CSV line. Capture next value in named group: 'val'
            \s*                      # Ignore leading whitespace.
            (?:                      # Group of value alternatives.
              ""                     # Either a double quoted string,
              (?<val>                # Capture contents between quotes.
                [^""]*(""""[^""]*)*  # Zero or more non-quotes, allowing 
              )                      # doubled "" quotes within string.
              ""\s*                  # Ignore whitespace following quote.
            |  (?<val>[^,]*)         # Or... zero or more non-commas.
            )                        # End value alternatives group.
            (?:,|$)                  # Match end is comma or EOS", 
            RegexOptions.Multiline | RegexOptions.IgnorePatternWhitespace)]
        private static partial Regex CSVOutput();
    }
}

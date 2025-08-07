namespace BlazorSecurityDemo.Authentication
{
    public class LinuxAuthenticationManager : ServerAuthenticationManager
    {
        public override async Task<UserAuthenticationDetails> CheckPasswordAsync(string username, string password)
        {
            // validate password against what is in /etc/shadow

            using StringWriter shadowsw = new();
            using StringWriter errorssw = new();

            // watch out for embedded quote characters

            string cleanedUsername = username.Replace("'", "\\'");
            string cleanedPassword = password.Replace("'", "\\'");

            string cmd = $"grep '^{cleanedUsername}:' /etc/shadow";
            var rc = await CommandProcessor.StartCommand(cmd, outputTextWriter: shadowsw, errorTextWriter: errorssw);
            if (rc != 0)
            {
                return new(username, false, [], []);
            }

            var parts = shadowsw.ToString().Split(':');
            string encryptedPassword = parts[1];

            var passwordParts = encryptedPassword.Split("$");
            if (passwordParts[0].Length > 0)
            {
                return new(username, false, [], []);
            }

            using StringWriter enchsw = new();
            if (passwordParts[1] == "6")
            {
                // Validate using sha-512

                cmd = $"mkpasswd -m sha-512 '{cleanedPassword}' '{passwordParts[2]}'";
                rc = await CommandProcessor.StartCommand(cmd, outputTextWriter: enchsw, errorTextWriter: errorssw);
                if (rc != 0)
                {
                    return new(username, false, [], []);
                }
            }
            else if (passwordParts[1] == "y")
            {
                // Validate using yescript

                cmd = $"mkpasswd '{cleanedPassword}' '${passwordParts[1]}${passwordParts[2]}${passwordParts[3]}'";
                rc = await CommandProcessor.StartCommand(cmd, outputTextWriter: enchsw, errorTextWriter: errorssw);
                if (rc != 0)
                {
                    return new(username, false, [], []);
                }
            }
            else
            {
                return new(username, false, [], []);
            }

            string generated = enchsw.ToString();
            if (generated.Trim() != encryptedPassword.Trim())
            {
                return new(username, false, [], []);
            }

            // get groups

            UserAuthenticationDetails response = new(username, true, [], []);
            if (!await GetGroups(response)) return new(username, false, [], []);

            return response;
        }

        private static async Task<bool> GetGroups(UserAuthenticationDetails response)
        {
            using StringWriter groupssw = new();
            using StringWriter errorssw = new();

            string cleanedUsername = response.Username.Replace("'", "\\'");
            string cmd = $"groups '{cleanedUsername}'";
            var rc = await CommandProcessor.StartCommand(cmd, outputTextWriter: groupssw, errorTextWriter: errorssw);
            if (rc != 0)
            {
                return false;
            }

            var groupList = groupssw.ToString().Split(" ");

            if (groupList.Length < 3 || groupList[0] != response.Username)
            {
                return false;
            }

            for (int gx = 3; gx < groupList.Length; gx++)
            {
                response.Groups.Add(groupList[gx]);
            }

            return true;
        }
    }
}

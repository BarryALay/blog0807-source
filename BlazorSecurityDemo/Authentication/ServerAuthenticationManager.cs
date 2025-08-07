namespace BlazorSecurityDemo.Authentication
{
    public class UserPrivilege(string name, bool isGranted)
    {
        public string Name { get; } = name;
        public bool IsGranted { get; } = isGranted;

        public override string ToString()
        {
            return $"{Name}: {IsGranted}";
        }
    }

    public class UserAuthenticationDetails(string username, bool isAuthenticated, List<string> groups, List<UserPrivilege> privileges)
    {
        public string Username { get; } = username;
        public bool IsAuthenticated { get; } = isAuthenticated;
        public List<string> Groups { get; } = groups;
        public List<UserPrivilege> Privileges { get; } = privileges;
    }

    public abstract class ServerAuthenticationManager
    {
        public abstract Task<UserAuthenticationDetails> CheckPasswordAsync(string username, string password);
    }
}

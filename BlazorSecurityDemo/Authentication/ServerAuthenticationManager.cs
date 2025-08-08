namespace BlazorSecurityDemo.Authentication
{
    /// <summary>
    /// Boolean-valued privilege assocated with user.
    /// </summary>
    /// <param name="name">Privilege name</param>
    /// <param name="isGranted">Indication of whether privilege is granted</param>
    public class UserPrivilege(string name, bool isGranted)
    {
        public string Name { get; } = name;
        public bool IsGranted { get; } = isGranted;

        public override string ToString()
        {
            return $"{Name}: {IsGranted}";
        }
    }

    /// <summary>
    /// Results of CheckPasswordAsync call.
    /// </summary>
    /// <param name="username">Username as provided</param>
    /// <param name="isAuthenticated">Indication of whether username/password validation was successful</param>
    /// <param name="groups">Groups associated with username</param>
    /// <param name="privileges">Privileges associate with username</param>
    public class UserAuthenticationDetails(string username, bool isAuthenticated, List<string> groups, List<UserPrivilege> privileges)
    {
        public string Username { get; } = username;
        public bool IsAuthenticated { get; } = isAuthenticated;
        public List<string> Groups { get; } = groups;
        public List<UserPrivilege> Privileges { get; } = privileges;
    }

    public abstract class ServerAuthenticationManager
    {
        /// <summary>
        /// Validate server username and password.
        /// </summary>
        /// <param name="username">Username on server</param>
        /// <param name="password">Password on server</param>
        /// <returns></returns>
        public abstract Task<UserAuthenticationDetails> CheckPasswordAsync(string username, string password);
    }
}

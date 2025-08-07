using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;

namespace BlazorSecurityDemo.Authentication
{
    public class UserAuthenticationStateProvider(ServerAuthenticationManager serverAuthenticationManager) : AuthenticationStateProvider
    {
        private readonly ServerAuthenticationManager serverAuthenticationManager = serverAuthenticationManager;
        private readonly AuthenticationState authenticationState = new(new ClaimsPrincipal());

        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            return Task.FromResult(authenticationState);
        }

        public async Task<bool> AuthenticateUserPasswordAsync(string username, string password)
        {
            // verify username and password
            var details = await serverAuthenticationManager.CheckPasswordAsync(username, password);
            if (!details.IsAuthenticated) return false;

            IList<Claim> claims = [
                new Claim(ClaimTypes.Name, username),
                .. details.Groups.ConvertAll(group => new Claim(ClaimTypes.Role, group)),
                .. details.Privileges.ConvertAll(privilege => new Claim(privilege.Name, privilege.IsGranted.ToString(), ClaimValueTypes.Boolean))
                ];

            var identity = new ClaimsIdentity(claims, "AuthenticateUser");
            var user = new ClaimsPrincipal(identity);

            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));

            return true;
        }

        public void Logout()
        {
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(new ClaimsPrincipal())));
        }
    }
}

using BlazorSecurityDemo.Authentication;
using BlazorSecurityDemo.Components;
using Microsoft.AspNetCore.Components.Authorization;
using System.Runtime.InteropServices;

namespace BlazorSecurityDemo
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddRazorComponents()
                .AddInteractiveServerComponents();

            builder.Services.AddAuthentication();
            builder.Services.AddCascadingAuthenticationState();

            builder.Services.AddScoped<AuthenticationStateProvider, UserAuthenticationStateProvider>();

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                builder.Services.AddScoped<ServerAuthenticationManager, WindowsAuthenticationManager>();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                builder.Services.AddScoped<ServerAuthenticationManager, LinuxAuthenticationManager>();
            }

            // Add policies
            builder.Services.AddAuthorizationBuilder().AddPolicy("admin", policy =>
            {
                // either Windows admin or Linux sudoer
                policy.RequireRole(["BUILTIN\\Administrators", "sudo"]);
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseAntiforgery();

            app.MapStaticAssets();
            app.MapRazorComponents<App>()
                .AddInteractiveServerRenderMode();

            app.Run();
        }
    }
}

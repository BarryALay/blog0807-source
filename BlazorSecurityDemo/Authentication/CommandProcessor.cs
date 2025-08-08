using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;

namespace BlazorSecurityDemo.Authentication
{
    /// <summary>
    /// Process commands using the server's command shell.
    /// From: https://stackoverflow.com/questions/139593/processstartinfo-hanging-on-waitforexit-why
    /// </summary>
    public static class CommandProcessor
    {
        /// <summary>
        /// Start a shell command.
        /// </summary>
        /// <param name="command">Shell command.</param>
        /// <param name="shell">Optional name of shell.  Defaults to basic shell for OS.</param>
        /// <param name="workingDirectory">Working directory for process</param>
        /// <param name="userid">Userid to run command under.  Only valid for Windows platform.</param>
        /// <param name="password">Password for userid.  Only valid for Windows platform.</param>
        /// <param name="timeout">Process timeout in milliseconds</param>
        /// <param name="outputTextWriter">Writer for standard output</param>
        /// <param name="errorTextWriter">Writer for standard error</param>
        /// <returns>The exit code from the command, or -1 if the userid/password is incorrect</returns>
        /// <exception cref="NotImplementedException">Current operating system is not supported.</exception>
        public static Task<int> StartCommand(
            string command,
            string? shell = null,
            string? workingDirectory = null,
            string? userid = null,
            string? password = null,
            int? timeout = null,
            TextWriter? outputTextWriter = null,
            TextWriter? errorTextWriter = null)
        {
            string escaped = "\"" + command.Replace("\"", "\\\"") + "\"";
            string arguments;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                shell ??= "cmd.exe";
                arguments = "/c " + escaped;
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                shell ??= "/bin/sh";
                arguments = "-c " + escaped;
            }
            else
            {
                throw new NotImplementedException($"Operating system {RuntimeInformation.OSDescription} not supported");
            }

            return StartProcess(
                shell, arguments,
                workingDirectory: workingDirectory,
                userid: userid,
                password: password,
                timeout: timeout,
                outputTextWriter: outputTextWriter,
                errorTextWriter: errorTextWriter
                );
        }

        /// <summary>
        /// Start a command shell process.
        /// </summary>
        /// <param name="filename">Name of command</param>
        /// <param name="arguments">Command-line arguments for command</param>
        /// <param name="workingDirectory">Working directory for process</param>
        /// <param name="userid">Userid to run command under.  Only valid for Windows platform.</param>
        /// <param name="password">Password for userid.  Only valid for Windows platform.</param>
        /// <param name="timeout">Process timeout in milliseconds</param>
        /// <param name="outputTextWriter">Writer for standard output</param>
        /// <param name="errorTextWriter">Writer for standard error</param>
        /// <returns>The exit code from the command, or -1 if the userid/password is incorrect</returns>
        public static async Task<int> StartProcess(
            string filename,
            string arguments,
            string? workingDirectory = null,
            string? userid = null,
            string? password = null,
            int? timeout = null,
            TextWriter? outputTextWriter = null,
            TextWriter? errorTextWriter = null)
        {
            using var process = new Process()
            {
                StartInfo = new ProcessStartInfo()
                {
                    CreateNoWindow = true,
                    Arguments = arguments,
                    FileName = filename,
                    RedirectStandardOutput = outputTextWriter != null,
                    RedirectStandardError = errorTextWriter != null,
                    UseShellExecute = false,
                    WorkingDirectory = workingDirectory
                }
            };

            if (userid != null && password != null)
            {
                process.StartInfo.UserName = userid;

                SecureString pwd = new();
                foreach (var ch in password)
                {
                    pwd.AppendChar(ch);
                }

#pragma warning disable CA1416 // Validate platform compatibility
                process.StartInfo.Password = pwd;
#pragma warning restore CA1416 // Validate platform compatibility
            }

            var cancellationTokenSource = timeout.HasValue ?
                new CancellationTokenSource(timeout.Value) :
                new CancellationTokenSource();

            try
            {
                process.Start();
            }
            catch (Exception)
            {
                return -1;
            }

            var tasks = new List<Task>(3) { process.WaitForExitAsync(cancellationTokenSource.Token) };
            if (outputTextWriter != null)
            {
                tasks.Add(ReadAsync(
                    x =>
                    {
                        process.OutputDataReceived += x;
                        process.BeginOutputReadLine();
                    },
                    x => process.OutputDataReceived -= x,
                    outputTextWriter,
                    cancellationTokenSource.Token));
            }

            if (errorTextWriter != null)
            {
                tasks.Add(ReadAsync(
                    x =>
                    {
                        process.ErrorDataReceived += x;
                        process.BeginErrorReadLine();
                    },
                    x => process.ErrorDataReceived -= x,
                    errorTextWriter,
                    cancellationTokenSource.Token));
            }

            await Task.WhenAll(tasks);
            return process.ExitCode;
        }

        /// <summary>
        /// Waits asynchronously for the process to exit.
        /// </summary>
        /// <param name="process">The process to wait for cancellation.</param>
        /// <param name="cancellationToken">A cancellation token. If invoked, the task will return
        /// immediately as cancelled.</param>
        /// <returns>A Task representing waiting for the process to end.</returns>
        public static Task WaitForExitAsync(
            this Process process,
            CancellationToken cancellationToken = default)
        {
            process.EnableRaisingEvents = true;

            var taskCompletionSource = new TaskCompletionSource<object?>();

            void handler(object? sender, EventArgs args)
            {
                process.Exited -= handler;
                _ = taskCompletionSource.TrySetResult(null);
            }

            process.Exited += handler;

            if (cancellationToken != default)
            {
                cancellationToken.Register(
                    () =>
                    {
                        process.Exited -= handler;
                        taskCompletionSource.TrySetCanceled();
                    });
            }

            return taskCompletionSource.Task;
        }

        /// <summary>
        /// Reads the data from the specified data recieved event and writes it to the
        /// <paramref name="textWriter"/>.
        /// </summary>
        /// <param name="addHandler">Adds the event handler.</param>
        /// <param name="removeHandler">Removes the event handler.</param>
        /// <param name="textWriter">The text writer.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public static Task ReadAsync(
            this Action<DataReceivedEventHandler> addHandler,
            Action<DataReceivedEventHandler> removeHandler,
            TextWriter textWriter,
            CancellationToken cancellationToken = default)
        {
            var taskCompletionSource = new TaskCompletionSource<object?>();

            DataReceivedEventHandler? handler = null;
            handler = new DataReceivedEventHandler(
                (sender, e) =>
                {
                    if (e.Data == null)
                    {
                        if (handler != null)
                            removeHandler(handler);
                        taskCompletionSource.TrySetResult(null);
                    }
                    else
                    {
                        textWriter.WriteLine(e.Data);
                    }
                });

            addHandler(handler);

            if (cancellationToken != default)
            {
                cancellationToken.Register(
                    () =>
                    {
                        removeHandler(handler);
                        taskCompletionSource.TrySetCanceled();
                    });
            }

            return taskCompletionSource.Task;
        }
    }
}

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;

namespace BlazorSecurityDemo.Authentication
{
    public static class CommandProcessor
    {
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

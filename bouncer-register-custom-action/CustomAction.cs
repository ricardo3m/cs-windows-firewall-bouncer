using Microsoft.Deployment.WindowsInstaller;
using System;
using System.Diagnostics;
using System.IO;

namespace bouncer_register_custom_action
{
    public static class CustomActions
    {
        private static readonly string CscliPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "CrowdSec", "cscli.exe");

        private static string registerBouncer(string bouncerPrefix)
        {
            string suffix = DateTime.Now.ToString("yyyyMMddHHmmssffff");
            using Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.FileName = CscliPath;
            p.StartInfo.Arguments = string.Format("-oraw bouncers add {0}{1}", bouncerPrefix, suffix);
            p.StartInfo.CreateNoWindow = true;
            p.Start();
            bool exited = p.WaitForExit(30000);
            if (!exited)
            {
                p.Kill();
                throw new TimeoutException("cscli.exe did not finish within 30 seconds");
            }
            string output = p.StandardOutput.ReadToEnd().Trim();
            if (p.ExitCode != 0)
            {
                throw new InvalidOperationException(string.Format("cscli.exe exited with code {0}. Output: {1}", p.ExitCode, output));
            }
            return output;
        }

        private static void updateBouncerConfig(string apiKey, string configPath)
        {
            string content = File.ReadAllText(configPath);
            content = content.Replace("${API_KEY}", apiKey);
            File.WriteAllText(configPath, content);
        }

        private static bool alreadyRegistered(string configPath)
        {
            string content = File.ReadAllText(configPath);
            return !content.Contains("${API_KEY}");
        }

        [CustomAction]
        public static ActionResult RegisterBouncer(Session session)
        {
            session.Log("Begin bouncer registration custom action");
            
            if (session.CustomActionData == null)
            {
                session.Log("BouncerRegistration: no custom data passed, exiting.");
                return ActionResult.Failure;
            }

            if (!session.CustomActionData.TryGetValue("bouncerPrefix", out string bouncerPrefix))
            {
                session.Log("missing bouncerPrefix param, exiting.");
                return ActionResult.Failure;
            }

            if (!session.CustomActionData.TryGetValue("bouncerConfigPath", out string bouncerConfigPath))
            {
                session.Log("missing bouncerConfigPath param, exiting.");
                return ActionResult.Failure;
            }

            if (alreadyRegistered(bouncerConfigPath))
            {
                session.Log("Seems like a bouncer {0} is already registered.", bouncerPrefix);
                return ActionResult.Success;
            }

            string apiKey = registerBouncer(bouncerPrefix);
            updateBouncerConfig(apiKey, bouncerConfigPath);
            
            session.Log("End of bouncer registration custom action");
            return ActionResult.Success;
        }
    }
}

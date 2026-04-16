using System;
using System.Collections.Generic;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using CommandLine;

using Fw;
using Cfg;
using Manager;

namespace cs_windows_firewall_bouncer
{
    class Program
    {
        private static readonly string[] AllowedFWProfiles = new string[] { "domain", "private", "public" };
        private static CancellationTokenSource consoleCts;

        public class Options
        {
            [Option('c', "config", Required = false, Default = "C:\\ProgramData\\CrowdSec\\config\\bouncers\\cs-windows-firewall-bouncer.yaml", HelpText = "Path to the config file")]
            public string Config { get; set; }
            [Option('r', "remove", Required = false, Default = false, HelpText = "Delete all crowdsec firewall rules and exit")]
            public bool RemoveAll { get; set; }
            [Option('d', "debug", Required = false, Default = false, HelpText = "Enable debug logging")]
            public bool Debug { get; set; }

            [Option('t', "trace", Required = false, Default = false, HelpText = "Enable trace logging")]
            public bool Trace { get; set; }
        }

        private static NLog.LogLevel GetLogLevel(string name) => name.ToLowerInvariant() switch
        {
            "trace" => NLog.LogLevel.Trace,
            "debug" => NLog.LogLevel.Debug,
            "info"  => NLog.LogLevel.Info,
            "warn"  => NLog.LogLevel.Warn,
            "error" => NLog.LogLevel.Error,
            "fatal" => NLog.LogLevel.Fatal,
            _       => NLog.LogLevel.Info,
        };

        protected static void consoleHandler(object sender, ConsoleCancelEventArgs args)
        {
            args.Cancel = true;
            consoleCts?.Cancel();
        }

        private static NLog.LogLevel DetermineLogLevel(BouncerConfig config, Options opts)
        {
            var logLevel = NLog.LogLevel.Info;
            if (!string.IsNullOrEmpty(config.config.LogLevel))
            {
                logLevel = GetLogLevel(config.config.LogLevel);
            }
            if (opts.Debug)
            {
                logLevel = NLog.LogLevel.Debug;
            }
            if (opts.Trace)
            {
                logLevel = NLog.LogLevel.Trace;
            }
            return logLevel;
        }

        private static bool TryConfigureLogging(NLog.Config.LoggingConfiguration loggerConfig, NLog.LogLevel logLevel, BouncerConfig config)
        {
            if (config.config.LogMedia == "file" || !Environment.UserInteractive)
            {
                if (string.IsNullOrEmpty(config.config.LogDir))
                {
                    config.config.LogDir = "C:\\ProgramData\\CrowdSec\\log";
                }
                var logfile = new NLog.Targets.FileTarget("logfile") { FileName = System.IO.Path.Combine(config.config.LogDir, "cs_windows_firewall_bouncer.log") };
                loggerConfig.AddRule(logLevel, NLog.LogLevel.Fatal, logfile);
            }
            else if (config.config.LogMedia == "console")
            {
                var logconsole = new NLog.Targets.ConsoleTarget("logconsole");
                loggerConfig.AddRule(logLevel, NLog.LogLevel.Fatal, logconsole);
            }
            else
            {
                Console.WriteLine("Unknown value for log_media: {0}", config.config.LogMedia);
                return false;
            }
            return true;
        }

        private static bool ValidateFwProfiles(NLog.Logger logger, List<string> profiles)
        {
            foreach (var profile in profiles)
            {
                var pos = Array.IndexOf(AllowedFWProfiles, profile);
                if (pos == -1)
                {
                    logger.Fatal("Invalid value {0} for fw_profiles: must be one of 'domain', 'public' or 'private'", profile);
                    return false;
                }
            }
            return true;
        }

        private static async Task RunInteractiveModeAsync(BouncerConfig config, CancellationToken token, NLog.Logger logger)
        {
            logger.Info("Running in interactive mode");
            DecisionsManager mgr = new(config);
            await mgr.Run(token);
            try
            {
                Firewall firewall = new(null);
                logger.Info("Deleted all firewall rules.");
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Failed to clean up firewall rules");
            }
        }

        static async Task Main(string[] args)
        {
            BouncerConfig config;
            Options opts;

            consoleCts = new CancellationTokenSource();
            Console.CancelKeyPress += new ConsoleCancelEventHandler(consoleHandler);

            var result = Parser.Default.ParseArguments<Options>(args).WithNotParsed(errors =>
            {
                foreach (var err in errors)
                {
                    Console.WriteLine("Error while parsing arguments: {0}", err.ToString());
                }
            }
            );

            opts = (result as Parsed<Options>)?.Value;
            if (opts == null)
            {
                return;
            }
            try
            {
                config = new(opts.Config);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Could not load configuration: {0}", ex.ToString());
                return;
            }

            var loggerConfig = new NLog.Config.LoggingConfiguration();
            var logLevel = DetermineLogLevel(config, opts);
            if (!TryConfigureLogging(loggerConfig, logLevel, config))
            {
                return;
            }

            NLog.LogManager.Configuration = loggerConfig;

            NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

            if (opts.RemoveAll)
            {
                try
                {
                    Firewall firewall = new(null);
                    Logger.Info("Deleted all firewall rules.");
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, "Failed to delete firewall rules");
                }
                return;
            }

            if (config.config.FwProfiles != null && !ValidateFwProfiles(Logger, config.config.FwProfiles))
            {
                return;
            }

            if (!Environment.UserInteractive)
            {
                //Running in a service
                Logger.Info("Running in service mode");
                try
                {
                    ServiceBase.Run(new Service(config));
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, "Exception while starting service");
                }
            }
            else
            {
                await RunInteractiveModeAsync(config, consoleCts.Token, Logger);
            }
            consoleCts?.Dispose();
        }
    }
}

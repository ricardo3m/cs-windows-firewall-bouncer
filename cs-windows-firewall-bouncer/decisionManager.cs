using System;
using System.Threading;
using System.Threading.Tasks;

using Api;
using Cfg;
using Fw;

namespace Manager
{
    public class DecisionsManager
    {
        private readonly ApiClient apiClient;
        private readonly Firewall firewall;
        private readonly int interval;

        private readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();
        public DecisionsManager(BouncerConfig config)
        {
            apiClient = new(config.config.ApiKey, config.config.ApiEndpoint);
            interval = config.config.UpdateFrequency;
            if (interval <= 0)
            {
                interval = 10;
            }
            firewall = new Firewall(config.config.FwProfiles, config.config.BatchSize);

            if (!firewall.IsEnabled())
            {
                throw new Exception("Firewall is not enabled for the current profile, the bouncer won't work.");
            }
            Logger.Debug("Firewall is enabled for profile {0}", firewall.GetCurrentProfile());
        }

        public async Task Run(CancellationToken ct = default)
        {
            var intervalms = this.interval * 1000;
            var startup = true;
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var decisions = await apiClient.GetDecisions(startup, ct);
                    if (decisions == null)
                    {
                        Logger.Error("Could not get decisions from LAPI. (startup: {0})", startup);
                    }
                    else
                    {
                        if (startup)
                        {
                            startup = false;
                        }
                        firewall.UpdateRule(decisions);
                    }
                    await Task.Delay(intervalms, ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }
}

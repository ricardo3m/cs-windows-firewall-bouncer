using System;
using System.Threading;
using System.Threading.Channels;
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
        private readonly Channel<DecisionStreamResponse> decisionsChannel;

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
                throw new InvalidOperationException("Firewall is not enabled for the current profile, the bouncer won't work.");
            }
            Logger.Debug("Firewall is enabled for profile {0}", firewall.GetCurrentProfile());

            decisionsChannel = Channel.CreateBounded<DecisionStreamResponse>(new BoundedChannelOptions(100)
            {
                SingleWriter = true,
                SingleReader = true,
                FullMode = BoundedChannelFullMode.Wait
            });
        }

        public async Task Run(CancellationToken ct = default)
        {
            await Task.WhenAll(ProduceAsync(ct), ConsumeAsync(ct));
        }

        private async Task ProduceAsync(CancellationToken ct)
        {
            var intervalms = this.interval * 1000;
            var startup = true;
            try
            {
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
                            await decisionsChannel.Writer.WriteAsync(decisions, ct);
                        }
                        await Task.Delay(intervalms, ct);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, "Unexpected error in decisions loop, will retry");
                        try { await Task.Delay(intervalms, ct); } catch (OperationCanceledException) { break; }
                    }
                }
            }
            finally
            {
                decisionsChannel.Writer.Complete();
            }
        }

        private async Task ConsumeAsync(CancellationToken ct)
        {
            try
            {
                await foreach (var decisions in decisionsChannel.Reader.ReadAllAsync(ct))
                {
                    try
                    {
                        firewall.UpdateRule(decisions);
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, "Unexpected error applying firewall rules");
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                Logger.Debug("Consumer stopped due to cancellation");
            }
        }
    }
}

using System;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;

using Cfg;
using Fw;
using Manager;

namespace CS_Windows_Firewall_2026
{
    partial class Service : ServiceBase
    {

        private readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        private readonly BouncerConfig config;
        private DecisionsManager mgr;
        private CancellationTokenSource cts;
        private Task runTask;

        public Service(BouncerConfig config)
        {
            Logger.Debug("Creating new service object");
            this.config = config;
            CanPauseAndContinue = false;
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            Logger.Debug("Onstart service");
            cts = new CancellationTokenSource();
            mgr = new(config);
            runTask = mgr.Run(cts.Token);
            base.OnStart(args);
            Logger.Debug("Onstart service end");
        }

        protected override void OnStop()
        {
            Logger.Debug("Onstop service");
            cts?.Cancel();
            try { runTask?.Wait(TimeSpan.FromSeconds(10)); }
            catch (AggregateException ex) { Logger.Debug("Run task faulted during stop: {0}", ex.InnerException?.Message ?? ex.Message); }
            catch (Exception ex) { Logger.Debug("Run task exception during stop: {0}", ex.Message); }
            cts?.Dispose();
            try
            {
                Firewall firewall = new(null);
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to clean up firewall rules during stop: {0}", ex.Message);
            }
            Logger.Debug("Onstop service end");
        }
    }
}

using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;
using NetFwTypeLib;

using Api;

namespace Fw
{
    public class FirewallRule
    {
        private const int DefaultBatchSize = 10000;
        public int Capacity { get; }
        public int Length => content.Count;
        private readonly HashSet<string> content = new();
        private readonly string ruleName;
        private bool stale;

        private readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        public FirewallRule(int capacity = DefaultBatchSize)
        {
            Capacity = capacity > 0 ? capacity : DefaultBatchSize;
            ruleName = "crowdsec-blocklist-" + Guid.NewGuid().ToString();
            stale = false;
        }

        public override string ToString()
        {
            return string.Join(",", content);
        }

        public void AddIP(string ip)
        {
            content.Add(ip);
            stale = true;
        }
        public bool RemoveIP(string ip)
        {
            Logger.Trace("Removing IP {0} from rule {1}", ip, ruleName);
            var r = content.Remove(ip);
            if (r)
            {
                stale = true;
            }
            return r;
        }

        public bool HasIp(string ip)
        {
            return content.Contains(ip);
        }

        public string GetName()
        {
            return ruleName;
        }

        public bool IsStale()
        {
            return stale;
        }
        public void SetStale(bool s)
        {
            stale = s;
        }
    }

    public class Firewall
    {
        private const int DefaultBatchSize = 10000;
        private readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        private readonly INetFwMgr fwManager;
        private readonly INetFwPolicy2 policy;
        private readonly List<FirewallRule> rulesBucket = new();
        private readonly Dictionary<string, FirewallRule> ipIndex = new();
        private readonly int profiles;
        private readonly int bucketCapacity;

        private readonly Dictionary<string, int> profilesDict = new Dictionary<string, int> { { "domain", 1 }, { "private", 2 }, { "public", 4 } };



        public Firewall(List<string> fwprofiles, int capacity = DefaultBatchSize)
        {
            bucketCapacity = capacity > 0 ? capacity : DefaultBatchSize;
            fwManager = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));
            policy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            if (fwprofiles == null || fwprofiles.Count == 0)
            {
                profiles = policy.CurrentProfileTypes;
            } 
            else
            {
                Logger.Info("Enabling rules for profiles {0}", string.Join(',', fwprofiles));
                foreach (string p in fwprofiles)
                {
                    profiles |= profilesDict[p];
                }
            }
            DeleteAllRules();
        }

        public bool IsEnabled()
        {
            return fwManager.LocalPolicy.CurrentProfile.FirewallEnabled;
        }

        public string GetCurrentProfile()
        {
            return policy.CurrentProfileTypes.ToString();
        }

        public void DeleteRule(string name)
        {
            Logger.Info("Deleting FW rule {0}", name);
            try
            {
                policy.Rules.Remove(name);
            }
            catch (COMException ex)
            {
                Logger.Warn("Could not delete FW rule {0}: {1}", name, ex.Message);
            }
        }

        public void DeleteAllRules()
        {
            var toDelete = new List<string>();
            foreach (INetFwRule rule in policy.Rules)
            {
                if (rule.Name.StartsWith("crowdsec-blocklist"))
                {
                    toDelete.Add(rule.Name);
                }
            }
            foreach (var name in toDelete)
            {
                Logger.Debug("Deleting rule {0}", name);
                try
                {
                    policy.Rules.Remove(name);
                }
                catch (COMException ex)
                {
                    Logger.Warn("Could not delete rule {0}: {1}", name, ex.Message);
                }
            }
            rulesBucket.Clear();
            ipIndex.Clear();
        }

        private INetFwRule getRule(string name)
        {
            Logger.Trace("in get rule for {0}", name);
            INetFwRule rule;
            try
            {
                rule = policy.Rules.Item(name);
                return rule;
            }
            catch (COMException ex)
            {
                Logger.Debug("Could not find rule {0}: {1}", name, ex.Message);
            }
            return null;
        }

        public bool RuleExists(string name)
        {
            return getRule(name) != null;
        }

        public bool RuleIsEnabled(string name)
        {
            Logger.Trace("checking if rule {0} is enabled", name);
            var rule = getRule(name);

            if (rule != null)
            {
                return rule.Enabled;
            }
            return false;
        }

        private FirewallRule findBucketForIp(string ip)
        {
            Logger.Trace("Trying to find bucket for ip {0}", ip);
            return ipIndex.TryGetValue(ip, out var bucket) ? bucket : null;
        }

        private FirewallRule findAvailableBucket()
        {
            var rule = rulesBucket.FirstOrDefault(x => x.Length < x.Capacity);
            if (rule != null)
            {
                return rule;
            }
            var newRule = new FirewallRule(bucketCapacity);
            Logger.Info("Creating new rule {0}", newRule.GetName());
            CreateRule(newRule.GetName());
            rulesBucket.Add(newRule);
            return newRule;
        }


        private void LogIndexState()
        {
            if (!Logger.IsTraceEnabled) return;
            Logger.Trace("Index state: {0} IP(s) tracked across {1} bucket(s)", ipIndex.Count, rulesBucket.Count);
            foreach (var bucket in rulesBucket)
            {
                Logger.Trace("  Bucket {0} ({1}/{2}): [{3}]", bucket.GetName(), bucket.Length, bucket.Capacity, bucket.ToString());
            }
        }

        public void UpdateRule(DecisionStreamResponse decisions)
        {
            foreach (var decision in decisions.Deleted)
            {
                if (decision == null || string.IsNullOrEmpty(decision.value))
                {
                    Logger.Debug("Skipping deleted decision with null/empty value");
                    continue;
                }
                if (!ipIndex.TryGetValue(decision.value, out var bucket))
                {
                    Logger.Trace("was not able to find a bucket for deleting {0}", decision.value);
                    continue;
                }
                if (bucket.RemoveIP(decision.value))
                {
                    ipIndex.Remove(decision.value);
                }
            }

            foreach (var decision in decisions.New)
            {
                if (decision == null || string.IsNullOrEmpty(decision.value))
                {
                    Logger.Debug("Skipping new decision with null/empty value");
                    continue;
                }
                if (decision.type != "ban")
                {
                    Logger.Debug("Skipping decision for {0} with unsupported type '{1}'", decision.value, decision.type);
                    continue;
                }
                if (decision.simulated)
                {
                    Logger.Debug("Skipping simulated decision for {0}", decision.value);
                    continue;
                }
                if (ipIndex.ContainsKey(decision.value))
                {
                    Logger.Trace("{0} already exists in a bucket", decision.value);
                    continue;
                }
                var bucket = findAvailableBucket();
                bucket.AddIP(decision.value);
                ipIndex[decision.value] = bucket;
            }

            List<FirewallRule> toDelete = new();
            foreach (var rule in rulesBucket)
            {
                var content = rule.ToString();
                if (!rule.IsStale() && content.Length != 0)
                {
                    continue;
                }
                if (content.Length == 0)
                {
                    Logger.Debug("Adding bucket {0} to delete list", rule.GetName());
                    toDelete.Add(rule);
                    DeleteRule(rule.GetName());
                }
                else
                {
                    var fwRule = getRule(rule.GetName());
                    if (fwRule == null)
                    {
                        Logger.Warn("Rule {0} not found in firewall, skipping update", rule.GetName());
                        continue;
                    }
                    try
                    {
                        fwRule.RemoteAddresses = content;
                        fwRule.Enabled = true;
                        rule.SetStale(false);
                    }
                    catch (COMException ex)
                    {
                        Logger.Error("Failed to update firewall rule {0}: {1}", rule.GetName(), ex.Message);
                    }
                }
            }
            foreach (var fwRule in toDelete)
            {
                rulesBucket.Remove(fwRule);
            }
            LogIndexState();
        }

        public void CreateRule(string name)
        {
            if (RuleExists(name))
            {
                Logger.Debug("Rule {0} already exists, not doing anything", name);
                return;
            }
            Logger.Debug("Creating FW rule");
            INetFwRule2 rule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwRule"));
            rule.Name = name;
            rule.Description = "CrowdSec Managed rule";
            rule.Enabled = false;
            rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
            rule.Profiles = profiles;
            rule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            policy.Rules.Add(rule);
        }
    }
}
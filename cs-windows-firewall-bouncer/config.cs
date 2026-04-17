using System;
using System.Collections.Generic;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Cfg
{
    public class Config
    {
        public string ApiEndpoint { get; set; } = "";
        public string ApiKey { get; set; } = "";
        public string LogLevel { get; set; } = "";
        public int UpdateFrequency { get; set; }
        public string LogMedia { get; set; } = "file";
        public string LogDir { get; set; } = "";
        public List<string> FwProfiles { get; set; }
        public int BatchSize { get; set; }
    }

    public class BouncerConfig
    {
        private readonly string configPath;
        public Config config { get; set; }
        public BouncerConfig(string configPath)
        {
            this.configPath = configPath;
            this.loadConfig();
        }

        private void loadConfig()
        {
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .Build();

            using (var reader = new System.IO.StreamReader(this.configPath))
            {
                config = deserializer.Deserialize<Config>(reader.ReadToEnd());
            }

            if (config == null)
                throw new ArgumentException("Configuration file is empty or invalid");

            if (string.IsNullOrWhiteSpace(config.ApiEndpoint))
                throw new ArgumentException("api_endpoint must be set in configuration");
            if (string.IsNullOrWhiteSpace(config.ApiKey))
                throw new ArgumentException("api_key must be set in configuration");
            if (config.ApiKey.StartsWith("${") && config.ApiKey.EndsWith("}"))
                throw new ArgumentException("api_key contains an unexpanded template placeholder; replace it with a real API key");
            if (config.UpdateFrequency < 0)
                throw new ArgumentException("update_frequency cannot be negative");
        }
    }

}
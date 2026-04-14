using System.IO;
using Xunit;
using Cfg;

namespace Tests
{
    public class ConfigTests
    {
        private static BouncerConfig LoadFromYaml(string yaml)
        {
            var path = Path.GetTempFileName();
            File.WriteAllText(path, yaml);
            try
            {
                return new BouncerConfig(path);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void ValidConfig_LoadsCorrectly()
        {
            var config = LoadFromYaml(@"
api_endpoint: http://localhost:8080
api_key: testkey
update_frequency: 10
log_media: console
");
            Assert.Equal("http://localhost:8080", config.config.ApiEndpoint);
            Assert.Equal("testkey", config.config.ApiKey);
            Assert.Equal(10, config.config.UpdateFrequency);
            Assert.Equal("console", config.config.LogMedia);
        }

        [Fact]
        public void BatchSize_IsDeserializedCorrectly()
        {
            var config = LoadFromYaml(@"
api_endpoint: http://localhost:8080
api_key: testkey
batch_size: 500
");
            Assert.Equal(500, config.config.BatchSize);
        }

        [Fact]
        public void MissingBatchSize_DefaultsToZero()
        {
            var config = LoadFromYaml(@"
api_endpoint: http://localhost:8080
api_key: testkey
");
            Assert.Equal(0, config.config.BatchSize);
        }

        [Fact]
        public void MissingLogLevel_DefaultsToEmptyString()
        {
            var config = LoadFromYaml(@"
api_endpoint: http://localhost:8080
api_key: testkey
");
            Assert.Equal("", config.config.LogLevel);
        }

        [Fact]
        public void MissingLogDir_DefaultsToEmptyString()
        {
            var config = LoadFromYaml(@"
api_endpoint: http://localhost:8080
api_key: testkey
");
            Assert.Equal("", config.config.LogDir);
        }

        [Fact]
        public void MissingLogMedia_DefaultsToFile()
        {
            var config = LoadFromYaml(@"
api_endpoint: http://localhost:8080
api_key: testkey
");
            Assert.Equal("file", config.config.LogMedia);
        }

        [Fact]
        public void MissingApiEndpoint_Throws()
        {
            Assert.Throws<System.ArgumentException>(() => LoadFromYaml(@"
api_key: testkey
"));
        }

        [Fact]
        public void MissingApiKey_Throws()
        {
            Assert.Throws<System.ArgumentException>(() => LoadFromYaml(@"
api_endpoint: http://localhost:8080
"));
        }

        [Fact]
        public void NegativeUpdateFrequency_Throws()
        {
            Assert.Throws<System.ArgumentException>(() => LoadFromYaml(@"
api_endpoint: http://localhost:8080
api_key: testkey
update_frequency: -1
"));
        }

        [Fact]
        public void EmptyConfig_Throws()
        {
            Assert.Throws<System.ArgumentException>(() => LoadFromYaml(""));
        }

        [Fact]
        public void ZeroUpdateFrequency_IsAllowed()
        {
            var config = LoadFromYaml(@"
api_endpoint: http://localhost:8080
api_key: testkey
update_frequency: 0
");
            Assert.Equal(0, config.config.UpdateFrequency);
        }

        [Fact]
        public void FwProfiles_AreDeserializedAsList()
        {
            var config = LoadFromYaml(@"
api_endpoint: http://localhost:8080
api_key: testkey
fw_profiles:
  - domain
  - private
");
            Assert.Equal(2, config.config.FwProfiles.Count);
            Assert.Contains("domain", config.config.FwProfiles);
            Assert.Contains("private", config.config.FwProfiles);
        }
    }
}

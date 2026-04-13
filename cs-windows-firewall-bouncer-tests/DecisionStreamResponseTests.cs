using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;
using Api;

namespace Tests
{
    public class DecisionStreamResponseTests
    {
        private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

        [Fact]
        public void Deserialize_NewDecisions()
        {
            var json = @"{
                ""new"": [
                    { ""id"": 1, ""origin"": ""cscli"", ""type"": ""ban"", ""scope"": ""ip"", ""value"": ""1.2.3.4"", ""duration"": ""24h"", ""scenario"": ""test"", ""simulated"": false }
                ],
                ""deleted"": []
            }";

            var result = JsonSerializer.Deserialize<DecisionStreamResponse>(json, JsonOptions);

            Assert.NotNull(result);
            Assert.Single(result.New);
            Assert.Empty(result.Deleted);
            Assert.Equal("1.2.3.4", result.New[0].value);
            Assert.Equal("ban", result.New[0].type);
            Assert.Equal("ip", result.New[0].scope);
        }

        [Fact]
        public void Deserialize_DeletedDecisions()
        {
            var json = @"{
                ""new"": [],
                ""deleted"": [
                    { ""id"": 2, ""origin"": ""cscli"", ""type"": ""ban"", ""scope"": ""ip"", ""value"": ""5.6.7.8"", ""duration"": ""24h"", ""scenario"": ""test"", ""simulated"": false }
                ]
            }";

            var result = JsonSerializer.Deserialize<DecisionStreamResponse>(json, JsonOptions);

            Assert.NotNull(result);
            Assert.Empty(result.New);
            Assert.Single(result.Deleted);
            Assert.Equal("5.6.7.8", result.Deleted[0].value);
        }

        [Fact]
        public void Deserialize_NullNewAndDeleted_ReturnsNullProperties()
        {
            var json = @"{}";

            var result = JsonSerializer.Deserialize<DecisionStreamResponse>(json, JsonOptions);

            Assert.NotNull(result);
            Assert.Null(result.New);
            Assert.Null(result.Deleted);
        }

        [Fact]
        public void Deserialize_MultipleDecisions()
        {
            var json = @"{
                ""new"": [
                    { ""id"": 1, ""value"": ""10.0.0.1"" },
                    { ""id"": 2, ""value"": ""10.0.0.2"" },
                    { ""id"": 3, ""value"": ""10.0.0.3"" }
                ],
                ""deleted"": [
                    { ""id"": 4, ""value"": ""192.168.1.1"" }
                ]
            }";

            var result = JsonSerializer.Deserialize<DecisionStreamResponse>(json, JsonOptions);

            Assert.Equal(3, result.New.Count);
            Assert.Single(result.Deleted);
        }

        [Fact]
        public void Deserialize_RangeScope()
        {
            var json = @"{
                ""new"": [
                    { ""id"": 1, ""scope"": ""range"", ""value"": ""192.168.1.0/24"", ""type"": ""ban"" }
                ],
                ""deleted"": []
            }";

            var result = JsonSerializer.Deserialize<DecisionStreamResponse>(json, JsonOptions);

            Assert.Equal("range", result.New[0].scope);
            Assert.Equal("192.168.1.0/24", result.New[0].value);
        }

        [Fact]
        public void Deserialize_SimulatedFlag()
        {
            var json = @"{
                ""new"": [
                    { ""id"": 1, ""value"": ""1.1.1.1"", ""simulated"": true }
                ],
                ""deleted"": []
            }";

            var result = JsonSerializer.Deserialize<DecisionStreamResponse>(json, JsonOptions);

            Assert.True(result.New[0].simulated);
        }
    }
}

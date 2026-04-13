using System;
using Xunit;
using Fw;

namespace Tests
{
    public class FirewallRuleTests
    {
        [Fact]
        public void NewRule_IsNotStale()
        {
            var rule = new FirewallRule();
            Assert.False(rule.IsStale());
        }

        [Fact]
        public void NewRule_IsEmpty()
        {
            var rule = new FirewallRule();
            Assert.Equal(0, rule.Length);
        }

        [Fact]
        public void DefaultCapacity_Is1000()
        {
            var rule = new FirewallRule();
            Assert.Equal(1000, rule.Capacity);
        }

        [Fact]
        public void CustomCapacity_IsRespected()
        {
            var rule = new FirewallRule(250);
            Assert.Equal(250, rule.Capacity);
        }

        [Fact]
        public void NonPositiveCapacity_FallsBackToDefault()
        {
            var rule0 = new FirewallRule(0);
            var ruleNeg = new FirewallRule(-5);
            Assert.Equal(1000, rule0.Capacity);
            Assert.Equal(1000, ruleNeg.Capacity);
        }

        [Fact]
        public void AddIP_IncreasesLength()
        {
            var rule = new FirewallRule();
            rule.AddIP("1.2.3.4");
            Assert.Equal(1, rule.Length);
        }

        [Fact]
        public void AddIP_SetsStale()
        {
            var rule = new FirewallRule();
            rule.AddIP("1.2.3.4");
            Assert.True(rule.IsStale());
        }

        [Fact]
        public void AddIP_DuplicateNotCounted()
        {
            var rule = new FirewallRule();
            rule.AddIP("1.2.3.4");
            rule.AddIP("1.2.3.4");
            Assert.Equal(1, rule.Length);
        }

        [Fact]
        public void HasIp_ReturnsTrueAfterAdd()
        {
            var rule = new FirewallRule();
            rule.AddIP("10.0.0.1");
            Assert.True(rule.HasIp("10.0.0.1"));
        }

        [Fact]
        public void HasIp_ReturnsFalseForUnknownIp()
        {
            var rule = new FirewallRule();
            Assert.False(rule.HasIp("10.0.0.1"));
        }

        [Fact]
        public void RemoveIP_DecreasesLength()
        {
            var rule = new FirewallRule();
            rule.AddIP("1.2.3.4");
            rule.SetStale(false);
            rule.RemoveIP("1.2.3.4");
            Assert.Equal(0, rule.Length);
        }

        [Fact]
        public void RemoveIP_SetsStale()
        {
            var rule = new FirewallRule();
            rule.AddIP("1.2.3.4");
            rule.SetStale(false);
            rule.RemoveIP("1.2.3.4");
            Assert.True(rule.IsStale());
        }

        [Fact]
        public void RemoveIP_ReturnsTrueWhenFound()
        {
            var rule = new FirewallRule();
            rule.AddIP("1.2.3.4");
            Assert.True(rule.RemoveIP("1.2.3.4"));
        }

        [Fact]
        public void RemoveIP_ReturnsFalseWhenNotFound()
        {
            var rule = new FirewallRule();
            Assert.False(rule.RemoveIP("1.2.3.4"));
        }

        [Fact]
        public void RemoveIP_DoesNotSetStaleWhenNotFound()
        {
            var rule = new FirewallRule();
            rule.SetStale(false);
            rule.RemoveIP("99.99.99.99");
            Assert.False(rule.IsStale());
        }

        [Fact]
        public void SetStale_UpdatesValue()
        {
            var rule = new FirewallRule();
            rule.SetStale(true);
            Assert.True(rule.IsStale());
            rule.SetStale(false);
            Assert.False(rule.IsStale());
        }

        [Fact]
        public void ToString_ProducesCommaSeparatedIPs()
        {
            var rule = new FirewallRule();
            rule.AddIP("1.1.1.1");
            rule.AddIP("2.2.2.2");
            var result = rule.ToString();
            Assert.Contains("1.1.1.1", result);
            Assert.Contains("2.2.2.2", result);
            Assert.Contains(",", result);
        }

        [Fact]
        public void ToString_EmptyRuleIsEmptyString()
        {
            var rule = new FirewallRule();
            Assert.Equal("", rule.ToString());
        }

        [Fact]
        public void GetName_IsUnique()
        {
            var rule1 = new FirewallRule();
            var rule2 = new FirewallRule();
            Assert.NotEqual(rule1.GetName(), rule2.GetName());
        }

        [Fact]
        public void GetName_StartsWithCrowdsecBlocklist()
        {
            var rule = new FirewallRule();
            Assert.StartsWith("crowdsec-blocklist", rule.GetName());
        }
    }
}

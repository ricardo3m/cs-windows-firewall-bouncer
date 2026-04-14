using System;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;
using System.Reflection;

namespace Api
{

    public class Decision
    {
        public int id { get; set; }
        public string origin { get; set; }
        public string type { get; set; }
        public string scope { get; set; }
        public string value { get; set; }
        public string duration { get; set; }
        public string until { get; set; }
        public string scenario { get; set; }
        public bool simulated { get; set; }
    }

    public class DecisionStreamResponse
    {
        [JsonPropertyName("new")]
        public List<Decision> New { get; set; }
        [JsonPropertyName("deleted")]
        public List<Decision> Deleted { get; set; }
    }


    public class ApiClient
    {
        // HttpClient is intentionally kept as a long-lived instance per
        // https://learn.microsoft.com/dotnet/fundamentals/networking/http/httpclient-guidelines
        private readonly HttpClient client = new HttpClient();
        private readonly string apiEndpoint;
        private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

        private readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();
        public ApiClient(string apiKey, string apiEndpoint)
        {
            this.apiEndpoint = apiEndpoint.EndsWith('/') ? apiEndpoint : apiEndpoint + '/';
            var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "unknown";
            client.DefaultRequestHeaders.Add("X-Api-Key", apiKey);
            client.DefaultRequestHeaders.Add("User-Agent", $"cs-windows-fw-bouncer/{version}");
        }

        public async Task<DecisionStreamResponse> GetDecisions(bool startup, CancellationToken ct = default)
        {
            Logger.Debug("starting GetDecisions");
            DecisionStreamResponse decisions;
            try
            {
                var uri = apiEndpoint + "v1/decisions/stream?startup=" + startup.ToString().ToLower() + "&scopes=Ip,Range";
                Logger.Trace("requesting {0}", uri);
                var response = await client.GetAsync(uri, ct);
                var body = await response.Content.ReadAsStringAsync(ct);
                if (!response.IsSuccessStatusCode)
                {
                    Logger.Error("LAPI returned HTTP {0}: {1}", (int)response.StatusCode, body);
                    return null;
                }
                Logger.Trace("LAPI response: {0}", body);
                decisions = JsonSerializer.Deserialize<DecisionStreamResponse>(body, JsonOptions);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Logger.Error("Could not get decisions: {0}", ex.Message);
                return null;
            }
            if (decisions == null)
            {
                decisions = new DecisionStreamResponse();
            }
            if (decisions.New == null)
            {
                decisions.New = new List<Decision>();
            }
            if (decisions.Deleted == null)
            {
                decisions.Deleted = new List<Decision>();
            }
            Logger.Info("Got {0} IP to delete, {1} to add", decisions.Deleted.Count, decisions.New.Count);
            return decisions;
        }
    }
}

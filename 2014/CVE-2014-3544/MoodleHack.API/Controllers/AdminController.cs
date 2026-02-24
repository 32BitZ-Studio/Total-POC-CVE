using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using MoodleHack.API.Services;
using MoodleHack.Infrastructure.Data;

namespace MoodleHack.API.Controllers
{
    [Route("api/[controller]/[action]")]
    public class AdminController : ControllerBase
    {
        private readonly AppDbContext _dbContext;
        private readonly IConfiguration _configuration;
        private readonly SdoApiClient _sdoApiClient;

        public AdminController(AppDbContext dbContext, IConfiguration configuration, SdoApiClient sdoApiClient)
        {
            _dbContext = dbContext;
            _configuration = configuration;
            _sdoApiClient = sdoApiClient;
        }

        public async Task<IActionResult> GetAllAccounts(string token)
        {
            if (_configuration["TOKEN"] == token)
                return Ok(await _dbContext.Users.AsQueryable().Where(x => x.IsActive)
                    .ToArrayAsync());
            return Forbid();
        }

        public async Task<IActionResult> SyncAccounts(string token)
        {
            if (_configuration["TOKEN"] != token) return Forbid();
            foreach (var account in _dbContext.Users.AsQueryable().Where(x => x.IsActive))
            {
                var valid = await _sdoApiClient.Validate(account.Cookie);
                if (valid) continue;
                account.IsActive = false;
                _dbContext.Update(account);
            }
            await _dbContext.SaveChangesAsync();
            return Ok(_dbContext.Users.Where(x => x.IsActive).ToArray());
            
        }
        //Remove all
        //Get all accounts with roles
        //Sync all accounts
    }
}
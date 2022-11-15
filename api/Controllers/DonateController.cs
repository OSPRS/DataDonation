using DB.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Linq;
using System.Text;
using DB;

namespace API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class DonateController : ControllerBase
    {
        private readonly ILogger<DonateController> _logger;
        private readonly DatabaseContext _dbcontext;

        public DonateController(ILogger<DonateController> logger, DatabaseContext dbcontext)
        {
            _logger = logger;
            _dbcontext = dbcontext;
        }

        /// <summary>
        /// Submits a data Donation
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        // [RequestSizeLimit(100_000_000)]
        public async Task<ActionResult> Submit(JsonElement data)
        {
            // TODO: Add validation
            var dataDonation = new DataDonationEntry(
                Guid.NewGuid(), DateTime.Now, JsonSerializer.Serialize(data));
            await _dbcontext.DataDonationEntries.AddAsync(dataDonation);
            await _dbcontext.SaveChangesAsync();
            return Ok();
        }
    }
}

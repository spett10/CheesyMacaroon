using MacaroonTestApi.Repositories;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace MacaroonTestApi.Controllers
{
	[Route("[controller]")]
	[ApiController]
	public class MacaroonController : ControllerBase
	{
		private readonly IMacaroonRepository _macaroonRepository;

		public MacaroonController(IMacaroonRepository macaroonRepository)
		{
			_macaroonRepository = macaroonRepository;
		}

		// Dont give them out like free candy like this. But we just need to test with them. 
		[HttpGet]
		public IActionResult Get()
		{
			var caveats = new List<string>()
			{
				$"exp = {DateTimeOffset.Now.AddMinutes(1).ToUnixTimeSeconds()}",
				$"nbf = {DateTimeOffset.Now.AddMinutes(-1).ToUnixTimeSeconds()}"
			};

			var serializedMacaroon = _macaroonRepository.IssueMacaroon(caveats);

			return Ok(Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(serializedMacaroon)));
		}
	}
}

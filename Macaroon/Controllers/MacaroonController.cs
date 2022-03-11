using MacaroonTestApi.Filter;
using MacaroonTestApi.Middleware;
using MacaroonTestApi.Repositories;
using Microsoft.AspNetCore.Mvc;
using ServiceStack;
using System;
using System.Collections.Generic;

namespace MacaroonTestApi.Controllers
{
	[Microsoft.AspNetCore.Mvc.Route("[controller]")]
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

			return Ok(serializedMacaroon);
		}

		[HttpGet("attenuate/{user}")]
		[MacaroonAuthorize]
		public IActionResult Attenuate(string user)
		{
			var authorizingMacaroon = HttpContext.Items[MacaroonAuthorizationHeaderMiddleware.AuthorizingMacaroonItemName].ToString();

			// Prepare the 3rd party caveat for this particular user. The user then has to obtain the discharge macaroon at https://localhost to prove that they fulfill the predicate. 
			var extended = _macaroonRepository.ExtendMacaroon(authorizingMacaroon, new List<string>(), $"user == {user}", "https://localhost");

			return Ok(extended);
		}

		//TODO: issue discharge based on basic authentication, then get username and put in as claim. 
		[HttpGet("authenticate")]
		[InsecureBasicAuthenticationFilter("Soren", "password1234")]
		public IActionResult Authenticate()
		{
			return Ok("Test");
		}
	}
}

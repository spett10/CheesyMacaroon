using MacaroonCore;
using MacaroonTestApi.Middleware;
using MacaroonTestApi.Repositories;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;

namespace MacaroonTestApi.Controllers
{
	[ApiController]
	[Route("[controller]")]
	public class WeatherForecastController : ControllerBase
	{
		private static readonly string[] Summaries = new[]
		{
			"Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
		};

		private readonly ILogger<WeatherForecastController> _logger;
		private readonly IMacaroonRepository _macaroonRepository;

		public WeatherForecastController(ILogger<WeatherForecastController> logger, IMacaroonRepository macaroonRepository)
		{
			_logger = logger;
			_macaroonRepository = macaroonRepository;
		}

		[HttpGet]
		public IActionResult Attenuate(string user)
		{
			if (!HttpContext.Items.ContainsKey(MacaroonAuthorizationHeaderMiddleware.AuthorizingMacaroonItemName))
			{
				return Unauthorized();
			}

			var authorizingMacaroon = Base64UrlEncoder.Decode(HttpContext.Items[MacaroonAuthorizationHeaderMiddleware.AuthorizingMacaroonItemName].ToString());

			// Prepare the 3rd party caveat for this particular user. The user then has to obtain the discharge macaroon at https://example.com to prove that they fulfill the predicate. 
			var extended = _macaroonRepository.ExtendMacaroon(authorizingMacaroon, new List<string>(), $"user == {user}", "https://example.com");

			return Ok(extended);
		}

		[HttpGet]
		public IActionResult Get()
		{
			// TODO: Move all the below into an attribute we can decorate with. 
			if(!HttpContext.Items.ContainsKey(MacaroonAuthorizationHeaderMiddleware.AuthorizingMacaroonItemName))
			{
				return Unauthorized();
			}

			var authorizingMacaroon = HttpContext.Items[MacaroonAuthorizationHeaderMiddleware.AuthorizingMacaroonItemName].ToString();
			var discharges = new List<string>();

			if (HttpContext.Items.ContainsKey(MacaroonAuthorizationHeaderMiddleware.DischargeMacaroonsItemName))
			{
				discharges = HttpContext.Items[MacaroonAuthorizationHeaderMiddleware.DischargeMacaroonsItemName] as List<string>;
			}

			if(!_macaroonRepository.ValidateMacaroon(authorizingMacaroon, discharges, new SimplePredicateVerifier()))
			{
				return Unauthorized();
			}

			var rng = new Random();
			return Ok(Enumerable.Range(1, 5).Select(index => new WeatherForecast
			{
				Date = DateTime.Now.AddDays(index),
				TemperatureC = rng.Next(-20, 55),
				Summary = Summaries[rng.Next(Summaries.Length)]
			})
			.ToArray());
		}

		private class SimplePredicateVerifier : IPredicateVerifier
		{
			public bool Verify(string predicate)
			{
				try
				{

					var currentTime = DateTimeOffset.Now.ToUnixTimeSeconds();

					//TODO: This shows an issue with the interface, we might want access to all caveats at once? 

					if (predicate.StartsWith("exp = ") && predicate.Length > "exp = ".Length)
					{
						var expiry = predicate.Split(" = ")[1];

						var expiryTime = Convert.ToInt64(expiry);

						if (currentTime < expiryTime) return false;

						return true;

					}

					if (predicate.StartsWith("nbf = ") && predicate.Length > "nbf = ".Length)
					{
						var notBefore = predicate.Split(" = ")[1];

						var notBeforeTime = Convert.ToInt64(notBefore);

						if (notBeforeTime > currentTime) return false;

						return true;
					}

					return false;
				}
				catch (Exception)
				{
					return false;
				}
			}
		}
	}
}

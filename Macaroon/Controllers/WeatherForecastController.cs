using MacaroonCore;
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
		public IActionResult Get()
		{
			// TODO: Move to middleware or attribute? 
			if(!HttpContext.Items.ContainsKey("Bearer"))
			{
				return Unauthorized();
			}

			var bearer = Base64UrlEncoder.Decode(HttpContext.Items["Bearer"].ToString());
			if(!_macaroonRepository.ValidateMacaroon(bearer, new List<string>(), new SimplePredicateVerifier()))
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

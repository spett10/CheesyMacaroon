using MacaroonTestApi.Filter;
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


		// TODO: move this to another controller? 
		[HttpGet("attenuate/{user}")]
		[MacaroonAuthorize]
		public IActionResult Attenuate(string user)
		{
			var authorizingMacaroon = Base64UrlEncoder.Decode(HttpContext.Items[MacaroonAuthorizationHeaderMiddleware.AuthorizingMacaroonItemName].ToString());

			// Prepare the 3rd party caveat for this particular user. The user then has to obtain the discharge macaroon at https://example.com to prove that they fulfill the predicate. 
			var extended = _macaroonRepository.ExtendMacaroon(authorizingMacaroon, new List<string>(), $"user == {user}", "https://example.com");

			return Ok(extended);
		}

		[HttpGet]
		[MacaroonAuthorize]
		public IActionResult Get()
		{
			var rng = new Random();
			return Ok(Enumerable.Range(1, 5).Select(index => new WeatherForecast
			{
				Date = DateTime.Now.AddDays(index),
				TemperatureC = rng.Next(-20, 55),
				Summary = Summaries[rng.Next(Summaries.Length)]
			})
			.ToArray());
		}
	}
}

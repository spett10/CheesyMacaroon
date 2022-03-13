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

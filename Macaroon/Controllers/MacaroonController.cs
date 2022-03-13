using MacaroonCore;
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

		private readonly string _location = "https://localhost";

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
			var extended = _macaroonRepository.ExtendMacaroon(authorizingMacaroon, new List<string>(), $"user == {user}", _location);

			return Ok(extended);
		}

		// TODO: make post, the macaroon can be quite large. and sensitive stuff as a get url parameter is nasty - but you shoulndt execute in browser anyways. 
		// Construct a discharge macaroon based on authentication. 
		[HttpGet("authenticate/{macaroon}")]
		[InsecureBasicAuthenticationFilter("Soren", "password1234")]
		public IActionResult Authenticate(string macaroon)
		{
			var identity = HttpContext.Items["Identity"] as string;

			var predicateVerifier = new IdentityPredicateVerifier(new List<string>() { identity });

			try
			{
				var discharge = _macaroonRepository.IssueDischarge(macaroon, _location, new List<string>(), predicateVerifier);

				return Ok(discharge);
			}
			catch (Exception)
			{
				return BadRequest($"No caveat in {nameof(macaroon)} for this location '{_location}'.");
			}
		}

		private class IdentityPredicateVerifier : IPredicateVerifier
		{
			private readonly List<string> _allowedIdentity;

			public IdentityPredicateVerifier(List<string> allowedIdentities)
			{
				_allowedIdentity = allowedIdentities;
			}

			public bool Verify(string predicate)
			{
				if(predicate.StartsWith("user ==") && predicate.Length > "user ==".Length)
				{
					var identity = predicate.Substring("user ==".Length).Trim();

					if (_allowedIdentity.Contains(identity)) return true;
				}

				return false;
			}
		}
	}
}

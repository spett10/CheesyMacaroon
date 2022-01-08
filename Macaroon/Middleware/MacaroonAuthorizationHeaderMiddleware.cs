using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Linq;
using System.Threading.Tasks;

namespace MacaroonTestApi.Middleware
{
	public class MacaroonAuthorizationHeaderMiddleware
	{
		public const string AuthorizingMacaroonItemName = "AuthMacaroon";
		public const string DischargeMacaroonsItemName = "DischargeMacaroons";

		private readonly RequestDelegate _next;
		public MacaroonAuthorizationHeaderMiddleware(RequestDelegate next)
		{
			_next = next;
		}

		public async Task InvokeAsync(HttpContext context)
		{
			var authHeader = context.Request.Headers["Authorization"];

			if(authHeader.Count == 1)
			{
				var headerValue = authHeader[0];

				if (!string.IsNullOrEmpty(headerValue))
				{
					if(headerValue.StartsWith("Bearer ") && headerValue.Length > "Bearer ".Length)
					{
						var tokens = headerValue.Split(" ").Skip(1).ToList();

						if(tokens.Count > 1)
						{
							// Auth is the first by convention
							var authorizingMacaroon = tokens[0];
							context.Items.Add(AuthorizingMacaroonItemName, authorizingMacaroon);

							// Rest, if any, are discharges
							var discharges = tokens.Skip(1).ToList();
							if(discharges.Count > 1)
							{
								context.Items.Add(DischargeMacaroonsItemName, discharges);
							}
						}
					}
				}
			}

			await _next(context);
		}
	}

	public static class AuthHeaderMiddlewareExtensions
	{
		public static IApplicationBuilder UseAuthHeader(this IApplicationBuilder builder)
		{
			return builder.UseMiddleware<MacaroonAuthorizationHeaderMiddleware>();
		}
	}
}

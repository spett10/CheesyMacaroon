using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace MacaroonTestApi.Middleware
{
	public class AuthHeaderMiddleware
	{
		private readonly RequestDelegate _next;
		public AuthHeaderMiddleware(RequestDelegate next)
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
						var bearerToken = headerValue.Split(" ")[1]; //TODO: dont index in like this, check it. 
						context.Items.Add("Bearer", bearerToken);
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
			return builder.UseMiddleware<AuthHeaderMiddleware>();
		}
	}
}

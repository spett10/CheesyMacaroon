using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Text;

namespace MacaroonTestApi.Filter
{
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
	public class InsecureBasicAuthenticationFilter : Attribute, IAuthorizationFilter
	{

		//Dont do this at home! 
		private readonly string _username;
		private readonly string _password;

		public InsecureBasicAuthenticationFilter(string username, string password)
		{
			_username = username;
			_password = password;
		}

		public void OnAuthorization(AuthorizationFilterContext context)
		{
			var authHeader = context.HttpContext.Request.Headers["Authorization"].ToString();

			if (string.IsNullOrEmpty(authHeader))
			{
				context.Result = new UnauthorizedResult();
				return;
			}

			if(!(authHeader.StartsWith("Basic ") && authHeader.Length > "Basic ".Length))
			{
				context.Result = new UnauthorizedResult();
				return;
			}

			authHeader = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader.Split(" ")[1]));

			var tokens = authHeader.ToString().Split(':', 2);

			if(tokens.Length != 2)
			{
				context.Result = new UnauthorizedResult();
				return;
			}

			if(tokens[0].Equals(_username) && tokens[1].Equals(_password))
			{
				context.HttpContext.Items["Identity"] = tokens[0];
				return;
			}

			context.Result = new UnauthorizedResult();
		}
	}
}

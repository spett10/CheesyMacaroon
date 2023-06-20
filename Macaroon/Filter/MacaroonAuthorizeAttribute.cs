using MacaroonCore;
using MacaroonTestApi.Middleware;
using MacaroonTestApi.Repositories;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;

namespace MacaroonTestApi.Filter
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class MacaroonAuthorizeAttribute : Attribute, IAuthorizationFilter
    {
        private readonly IMacaroonRepository _macaroonRepository;

        private List<string> _predicates;

        public MacaroonAuthorizeAttribute()
        {
            _predicates = new List<string>();
            _macaroonRepository = new InMemoryMacaroonRepository();
        }

        public MacaroonAuthorizeAttribute(params string[] predicates)
        {
            _predicates = new List<string>();

            foreach (var predicate in predicates)
            {
                _predicates.Add(predicate);
            }

            _macaroonRepository = new InMemoryMacaroonRepository();
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            try
            {
                if (!context.HttpContext.Items.ContainsKey(MacaroonAuthorizationHeaderMiddleware.AuthorizingMacaroonItemName))
                {
                    context.Result = new UnauthorizedResult();
                    return;
                }

                var authorizingMacaroon = context.HttpContext.Items[MacaroonAuthorizationHeaderMiddleware.AuthorizingMacaroonItemName].ToString();
                var discharges = new List<string>();

                if (context.HttpContext.Items.ContainsKey(MacaroonAuthorizationHeaderMiddleware.DischargeMacaroonsItemName))
                {
                    discharges = context.HttpContext.Items[MacaroonAuthorizationHeaderMiddleware.DischargeMacaroonsItemName] as List<string>;
                }

                if (!_macaroonRepository.ValidateMacaroon(authorizingMacaroon, discharges, new SimplePredicateVerifier(_predicates)))
                {
                    context.Result = new UnauthorizedResult();
                    return;
                }
            }
            catch (Exception)
            {
                context.Result = new UnauthorizedResult();
            }
        }

        private class SimplePredicateVerifier : IPredicateVerifier
        {
            private readonly List<string> _predicates;

            public SimplePredicateVerifier()
            {
                _predicates = new List<string>();
            }

            public SimplePredicateVerifier(List<string> predicates)
            {
                _predicates = predicates;

            }

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

                        if (currentTime > expiryTime) return false;

                        return true;

                    }

                    if (predicate.StartsWith("nbf = ") && predicate.Length > "nbf = ".Length)
                    {
                        var notBefore = predicate.Split(" = ")[1];

                        var notBeforeTime = Convert.ToInt64(notBefore);

                        if (notBeforeTime > currentTime) return false;

                        return true;
                    }

                    if (_predicates.Contains(predicate))
                    {
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

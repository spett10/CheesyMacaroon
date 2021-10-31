using MacaroonCore;
using NUnit.Framework;
using System;
using System.Security.Cryptography;
using System.Text;
using Moq;
using System.Collections.Generic;
using System.Linq;

namespace MacaroonCoreTests
{
	public class MacaroonTests
	{
		[Test]
		public void CreateMacaroon_ShouldHaveValidMacOverId()
		{
			var key = KeyGen();

			var id = IdGen();

			var macaroon = Macaroon.CreateAuthorisingMacaroon(key, id);

			var expectedPayLoad = id;

			using (var hmac = new HMACSHA256(key))
			{
				var mac = hmac.ComputeHash(Encoding.UTF8.GetBytes(expectedPayLoad));
				Assert.AreEqual(macaroon.Signature, mac);
			}
		}

		#region FirstPartyCaveat only

		[Test]
		public void Verify_VerifierReturnsTrue_ShouldVerify()
		{
			var key = KeyGen();
			var id = IdGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key, id);

			var caveat = new FirstPartyCaveat("user == admin");

			authorisingMacaroon.AddFirstPartyCaveat(caveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.Is<string>(s => s.Equals("user == admin")))).Returns(true);

			var valid = authorisingMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(true));
		}

		[Test]
		public void Verify_VerifierReturnsFalse_ShouldNotVerify()
		{
			var key = KeyGen();
			var id = IdGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key, id);

			var caveat = new FirstPartyCaveat("user == admin");

			authorisingMacaroon.AddFirstPartyCaveat(caveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.Is<string>(s => s.Equals("user == admin")))).Returns(false);

			var valid = authorisingMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(false));
		}

		[Test]
		public void Verify_MultipleCaveats_AllValid_ShouldVerify()
		{
			var key = KeyGen();
			var id = IdGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key, id);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat)
								.AddFirstPartyCaveat(ipCaveat)
								.AddFirstPartyCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var valid = authorisingMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(true));
		}

		[Test]
		public void Verify_MultipleCaveats_OneOfThemInvalid_ShouldNotVerify()
		{
			var key = KeyGen();
			var id = IdGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key, id);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat)
								.AddFirstPartyCaveat(ipCaveat)
								.AddFirstPartyCaveat(expCaveat);

			var verifier = new VerifierMock("exp 1620000113");

			var valid = authorisingMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifier, key);

			Assert.That(valid, Is.EqualTo(false));
		}

		[Test]
		public void Verify_WrongKey_ShouldNotVerify()
		{
			var key = KeyGen();
			var id = IdGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key, id);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat)
								.AddFirstPartyCaveat(ipCaveat)
								.AddFirstPartyCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var someOtherKey = KeyGen();
			var someOtherMacaroon = Macaroon.CreateAuthorisingMacaroon(someOtherKey, id);

			var valid = authorisingMacaroon.Verify(someOtherMacaroon, new List<Macaroon>(), verifierMock.Object, someOtherKey);

			Assert.That(valid, Is.EqualTo(false));
		}

		[Test]
		public void Verify_AlterSignature_ShouldNotVerify()
		{
			var key = KeyGen();
			var id = IdGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key, id);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat)
								.AddFirstPartyCaveat(ipCaveat)
								.AddFirstPartyCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			authorisingMacaroon.Signature = new byte[32]; //The odds of the correct signature being this uninitialized memory is not something we worry about. 
			var valid = authorisingMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(false));
		}

		[Test]
		public void Verify_RemoveCaveat_ShouldNotVerify()
		{
			var key = KeyGen();
			var id = IdGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key, id);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat)
							   .AddFirstPartyCaveat(ipCaveat)
							   .AddFirstPartyCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			authorisingMacaroon.Caveats = authorisingMacaroon.Caveats.Skip(1).ToList();

			var valid = authorisingMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(false));
		}

		[Test]
		public void Verify_AlterCaveat_ShouldNotVerify()
		{
			var key = KeyGen();
			var id = IdGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key, id);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat)
								.AddFirstPartyCaveat(ipCaveat)
								.AddFirstPartyCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			/* We try and remove the admin requirement, because we're not an admin */
			authorisingMacaroon.Caveats[0] = new FirstPartyCaveat("user = trial");

			var valid = authorisingMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(false));
		}

		#endregion

		#region ThirdPartyCaveats 

		[Test]
		public void Verify_CreateDischargeMacaroon_PredicateNotValid_ShouldThrow()
		{
			var authorisingRootKey = KeyGen();
			var authId = IdGen();
			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(authorisingRootKey, authId);

			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var caveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(false);

			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, caveatRootKey, thirdPartyLocation, thirdPartyKey, out var caveatId);

			Assert.Throws<ArgumentException>(() => Macaroon.CreateDischargeMacaroon(thirdPartyKey, caveatId, thirdPartyLocation, verifierMock.Object));
		}

		[Test]
		public void Verify_CreateDischargeMacaroon_ValidPredicate_ShouldVerify()
		{
			var authorisingRootKey = KeyGen();
			var authId = IdGen();
			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(authorisingRootKey, authId);

			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var caveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, caveatRootKey, thirdPartyLocation, thirdPartyKey, out var caveatId);

			var dischargeMacaroon = Macaroon.CreateDischargeMacaroon(thirdPartyKey, caveatId, thirdPartyLocation, verifierMock.Object);
			
			var ipCaveat = new FirstPartyCaveat("ip = 192.0.10.168");
			var expCaveat = new FirstPartyCaveat("exp = 12345");

			dischargeMacaroon.AddFirstPartyCaveat(ipCaveat);
			dischargeMacaroon.AddFirstPartyCaveat(expCaveat);
			dischargeMacaroon.Finalize();

			var sealedDischargeMacaroons = authorisingMacaroon.PrepareForRequest(new List<Macaroon> { dischargeMacaroon });

			var valid = authorisingMacaroon.Verify(authorisingMacaroon, sealedDischargeMacaroons, verifierMock.Object, authorisingRootKey);
			Assert.That(valid, Is.EqualTo(true));
		}

		#endregion


		#region Helpers

		private byte[] KeyGen()
		{
			var csprng = RandomNumberGenerator.Create();
			var key = new byte[32];
			csprng.GetBytes(key);
			return key;
		}

		private string IdGen()
		{
			return Guid.NewGuid().ToString();
		}

		internal class VerifierMock : IPredicateVerifier
		{
			private readonly string _onlyPredicateWeDontAccept;

			public VerifierMock(string onlyCaveatWeDontAccept)
			{
				_onlyPredicateWeDontAccept = onlyCaveatWeDontAccept;
			}

			public bool Verify(string predicate)
			{
				return !predicate.Equals(_onlyPredicateWeDontAccept);
			}
		}

		#endregion

	}
}
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
		[SetUp]
		public void Setup()
		{
		}

		private byte[] KeyGen()
		{
			var csprng = RandomNumberGenerator.Create();
			var key = new byte[32];
			csprng.GetBytes(key);
			return key;
		}

		[Test]
		public void CreateMacaroon_ShouldHaveValidMacOverId()
		{
			var key = KeyGen();

			var id = Guid.NewGuid().ToString();

			var macaroon = new Macaroon(key, id);

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
			var id = Guid.NewGuid().ToString();
			
			var authorisingMacaroon = new Macaroon(key, id);

			var caveat = new FirstPartyCaveat("user == admin");

			var delegatedMacaroon = authorisingMacaroon.AddCaveat(caveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.Is<string>(s => s.Equals("user == admin")))).Returns(true);

			var valid = delegatedMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(true));
		}

		[Test]
		public void Verify_VerifierReturnsFalse_ShouldNotVerify()
		{
			var key = KeyGen();
			var id = Guid.NewGuid().ToString();

			var authorisingMacaroon = new Macaroon(key, id);

			var caveat = new FirstPartyCaveat("user == admin");

			var delegatedMacaroon = authorisingMacaroon.AddCaveat(caveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.Is<string>(s => s.Equals("user == admin")))).Returns(false);

			var valid = delegatedMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(false));
		}

		[Test]
		public void Verify_MultipleCaveats_AllValid_ShouldVerify()
		{
			var key = KeyGen();
			var id = Guid.NewGuid().ToString();

			var authorisingMacaroon = new Macaroon(key, id);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			var delegatedMacaroon = authorisingMacaroon.AddCaveat(adminCaveat)
													   .AddCaveat(ipCaveat)
													   .AddCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var valid = delegatedMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(true));
		}

		[Test]
		public void Verify_MultipleCaveats_OneOfThemInvalid_ShouldNotVerify()
		{
			var key = KeyGen();
			var id = Guid.NewGuid().ToString();

			var authorisingMacaroon = new Macaroon(key, id);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			var delegatedMacaroon = authorisingMacaroon.AddCaveat(adminCaveat)
													   .AddCaveat(ipCaveat)
													   .AddCaveat(expCaveat);

			var verifier = new VerifierMock("exp 1620000113");

			var valid = delegatedMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifier, key);

			Assert.That(valid, Is.EqualTo(false));
		}

		[Test]
		public void Verify_WrongAuthorisingMacaroon_ShouldNotVerify()
		{
			var key = KeyGen();
			var id = Guid.NewGuid().ToString();

			var authorisingMacaroon = new Macaroon(key, id);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			var delegatedMacaroon = authorisingMacaroon.AddCaveat(adminCaveat)
													   .AddCaveat(ipCaveat)
													   .AddCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var otherId = Guid.NewGuid().ToString();
			var someOtherMacaroon = new Macaroon(key, otherId);

			var valid = delegatedMacaroon.Verify(someOtherMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(false));
		}

		[Test]
		public void Verify_WrongKey_ShouldNotVerify()
		{
			var key = KeyGen();
			var id = Guid.NewGuid().ToString();

			var authorisingMacaroon = new Macaroon(key, id);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			var delegatedMacaroon = authorisingMacaroon.AddCaveat(adminCaveat)
													   .AddCaveat(ipCaveat)
													   .AddCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var someOtherKey = KeyGen();
			var someOtherMacaroon = new Macaroon(someOtherKey, id);

			var valid = delegatedMacaroon.Verify(someOtherMacaroon, new List<Macaroon>(), verifierMock.Object, someOtherKey);

			Assert.That(valid, Is.EqualTo(false));
		}

		[Test]
		public void Verify_AlterSignature_ShouldNotVerify()
		{
			var key = KeyGen();
			var id = Guid.NewGuid().ToString();

			var authorisingMacaroon = new Macaroon(key, id);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			var delegatedMacaroon = authorisingMacaroon.AddCaveat(adminCaveat)
													   .AddCaveat(ipCaveat)
													   .AddCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			delegatedMacaroon.Signature = new byte[32]; //The odds of the correct signature being this uninitialized memory is not something we worry about. 
			var valid = delegatedMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(false));
		}

		[Test]
		public void Verify_RemoveCaveat_ShouldNotVerify()
		{
			var key = KeyGen();
			var id = Guid.NewGuid().ToString();

			var authorisingMacaroon = new Macaroon(key, id);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			var delegatedMacaroon = authorisingMacaroon.AddCaveat(adminCaveat)
													   .AddCaveat(ipCaveat)
													   .AddCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			delegatedMacaroon.Caveats = delegatedMacaroon.Caveats.Skip(1).ToList();

			var valid = delegatedMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(false));
		}

		[Test]
		public void Verify_AlterCaveat_ShouldNotVerify()
		{
			var key = KeyGen();
			var id = Guid.NewGuid().ToString();

			var authorisingMacaroon = new Macaroon(key, id);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			var delegatedMacaroon = authorisingMacaroon.AddCaveat(adminCaveat)
													   .AddCaveat(ipCaveat)
													   .AddCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			/* We try and remove the admin requirement, because we're not an admin */
			delegatedMacaroon.Caveats[0] = new FirstPartyCaveat("user = trial");

			var valid = delegatedMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(false));
		}

		#endregion

		#region Helpers

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
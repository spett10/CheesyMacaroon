using MacaroonCore;
using NUnit.Framework;
using System;
using System.Security.Cryptography;
using System.Text;
using Moq;
using System.Collections.Generic;

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

		[Test]
		public void AddCaveat_ShouldVerify()
		{
			var key = KeyGen();
			var id = Guid.NewGuid().ToString();
			
			var authorisingMacaroon = new Macaroon(key, id);

			var caveat = new FirstPartyCaveat("user == admin");

			var delegatedMacaroon = authorisingMacaroon.AddCaveat(caveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.Is<string>(s => s.Equals("user == admin")))).Returns(true);

			// TODO: we fucked something up here. 
			var valid = delegatedMacaroon.Verify(authorisingMacaroon, new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(valid, Is.EqualTo(true));
		}
	}
}
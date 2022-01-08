using MacaroonCore;
using NUnit.Framework;
using System;
using System.Security.Cryptography;
using Moq;
using System.Collections.Generic;
using System.Linq;
using MacaroonCore.Exceptions;

namespace MacaroonCoreTests
{
	public class MacaroonTests
	{
		[Test]
		public void CreateMacaroon_ShouldHaveValidMacOverId()
		{
			var key = KeyGen();
			var macaroon = Macaroon.CreateAuthorisingMacaroon(key);

			var expectedPayLoad = macaroon.IdPayload;

			using (var hmac = new HMACSHA256(key))
			{
				var mac = hmac.ComputeHash(expectedPayLoad);
				Assert.AreEqual(macaroon.Signature, mac);
			}
		}

		#region FirstPartyCaveat only

		[Test]
		public void Verify_VerifierReturnsTrue_ShouldVerify()
		{
			var key = KeyGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key);

			var caveat = new FirstPartyCaveat("user == admin");

			authorisingMacaroon.AddFirstPartyCaveat(caveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.Is<string>(s => s.Equals("user == admin")))).Returns(true);

			var result = authorisingMacaroon.Validate(new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(result.IsValid, Is.EqualTo(true));
		}

		[Test]
		public void Verify_VerifierReturnsFalse_ShouldNotVerify()
		{
			var key = KeyGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key);

			var caveat = new FirstPartyCaveat("user == admin");

			authorisingMacaroon.AddFirstPartyCaveat(caveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.Is<string>(s => s.Equals("user == admin")))).Returns(false);

			var result = authorisingMacaroon.Validate(new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(result.IsValid, Is.EqualTo(false));
			Assert.That(result.MacaroonValidationException, Is.InstanceOf<InvalidPredicateException>());
		}

		[Test]
		public void Verify_MultipleCaveats_AllValid_ShouldVerify()
		{
			var key = KeyGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat)
								.AddFirstPartyCaveat(ipCaveat)
								.AddFirstPartyCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var result = authorisingMacaroon.Validate(new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(result.IsValid, Is.EqualTo(true));
		}

		[Test]
		public void Verify_MultipleCaveats_OneOfThemInvalid_ShouldNotVerify()
		{
			var key = KeyGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat)
								.AddFirstPartyCaveat(ipCaveat)
								.AddFirstPartyCaveat(expCaveat);

			var verifier = new VerifierMock("exp 1620000113");

			var result = authorisingMacaroon.Validate(new List<Macaroon>(), verifier, key);

			Assert.That(result.IsValid, Is.EqualTo(false));
			Assert.That(result.MacaroonValidationException, Is.InstanceOf<InvalidPredicateException>());
		}

		[Test]
		public void Verify_WrongKey_ShouldNotVerify()
		{
			var key = KeyGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat)
								.AddFirstPartyCaveat(ipCaveat)
								.AddFirstPartyCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var someOtherKey = KeyGen();
			var someOtherMacaroon = Macaroon.CreateAuthorisingMacaroon(someOtherKey);

			var result = authorisingMacaroon.Validate(someOtherMacaroon, new List<Macaroon>(), verifierMock.Object, someOtherKey);

			Assert.That(result.IsValid, Is.EqualTo(false));
			Assert.That(result.MacaroonValidationException, Is.InstanceOf<MacaroonAuthenticityException>());
		}

		[Test]
		public void Verify_AlterSignature_ShouldNotVerify()
		{
			var key = KeyGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat)
								.AddFirstPartyCaveat(ipCaveat)
								.AddFirstPartyCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			authorisingMacaroon.Signature = new byte[32]; //The odds of the correct signature being this uninitialized memory is not something we worry about. 
			var result = authorisingMacaroon.Validate(new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(result.IsValid, Is.EqualTo(false));
			Assert.That(result.MacaroonValidationException, Is.InstanceOf<MacaroonAuthenticityException>());
		}

		[Test]
		public void Verify_RemoveCaveat_ShouldNotVerify()
		{
			var key = KeyGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key);

			var adminCaveat = new FirstPartyCaveat("user = admin");
			var ipCaveat = new FirstPartyCaveat("ip = 198.162.0.1");
			var expCaveat = new FirstPartyCaveat("exp 1620000113");

			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat)
							   .AddFirstPartyCaveat(ipCaveat)
							   .AddFirstPartyCaveat(expCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			authorisingMacaroon.Caveats = authorisingMacaroon.Caveats.Skip(1).ToList();

			var result = authorisingMacaroon.Validate(new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(result.IsValid, Is.EqualTo(false));
			Assert.That(result.MacaroonValidationException, Is.InstanceOf<MacaroonAuthenticityException>());
		}

		[Test]
		public void Verify_AlterCaveat_ShouldNotVerify()
		{
			var key = KeyGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(key);

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

			var result = authorisingMacaroon.Validate(new List<Macaroon>(), verifierMock.Object, key);

			Assert.That(result.IsValid, Is.EqualTo(false));
			Assert.That(result.MacaroonValidationException, Is.InstanceOf<MacaroonAuthenticityException>());
		}

		#endregion

		#region ThirdPartyCaveats 

		[Test]
		public void CreateDischargeMacaroon_PredicateNotValid_ShouldThrow()
		{
			var authorisingRootKey = KeyGen();
			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(authorisingRootKey);

			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var caveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			/* The verifier will fail the predicate, so we cannot issue a discharge for the predicate. */
			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(false);

			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, caveatRootKey, thirdPartyLocation, thirdPartyKey, out var caveatId);

			Assert.Throws<ArgumentException>(() => Macaroon.CreateDischargeMacaroon(thirdPartyKey, caveatId, thirdPartyLocation, verifierMock.Object));
		}

		[Test]
		public void AddThirdPartyCaveat_CaveatIdShouldBeEncryptionOfRootKeyAndPredicateUnderThirdPartyKey()
		{
			var authorisingRootKey = KeyGen();
			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(authorisingRootKey);

			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var caveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, caveatRootKey, thirdPartyLocation, thirdPartyKey, out var caveatId);

			var caveatIdBytes = Encode.DefaultByteDecoder(caveatId);
			var plaintext = SymmetricCryptography.AesGcmDecrypt(thirdPartyKey, caveatIdBytes, Encode.DefaultStringDecoder(thirdPartyLocation));

			var rootKey = plaintext.Take(SymmetricCryptography.AesKeySizeInBytes).ToArray();
			var predicate = Encode.DefaultStringEncoder(plaintext.Skip(SymmetricCryptography.AesKeySizeInBytes).ToArray());

			Assert.That(rootKey, Is.EqualTo(caveatRootKey));
			Assert.That(predicate, Is.EqualTo(thirdPartyPredicate));
		}

		[Test]
		public void Verify_ThirdPartyCaveat_InvalidPredicate_ShouldNotVerify()
		{
			var authorisingRootKey = KeyGen();
			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(authorisingRootKey);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var caveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, caveatRootKey, thirdPartyLocation, thirdPartyKey, out var caveatId);

			var dischargeMacaroon = Macaroon.CreateDischargeMacaroon(thirdPartyKey, caveatId, thirdPartyLocation, verifierMock.Object);

			var ipCaveat = new FirstPartyCaveat("ip = 192.0.10.168");
			var expCaveat = new FirstPartyCaveat("exp = 12345");

			dischargeMacaroon.AddFirstPartyCaveat(ipCaveat);
			dischargeMacaroon.AddFirstPartyCaveat(expCaveat);
			dischargeMacaroon.Finalize();

			var sealedDischargeMacaroons = authorisingMacaroon.PrepareForRequest(new List<Macaroon> { dischargeMacaroon });

			/* Update verifier to be wrong */
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(false);

			var result = authorisingMacaroon.Validate(sealedDischargeMacaroons, verifierMock.Object, authorisingRootKey);
			Assert.That(result.IsValid, Is.EqualTo(false));
			Assert.That(result.MacaroonValidationException, Is.InstanceOf<InvalidPredicateException>());
		}

		[Test]
		public void Verify_ThirdPartyCaveat_With_FirstPartyCaveats_ValidPredicate_ShouldVerify()
		{
			var authorisingRootKey = KeyGen();
			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(authorisingRootKey);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var caveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, caveatRootKey, thirdPartyLocation, thirdPartyKey, out var caveatId);

			var dischargeMacaroon = Macaroon.CreateDischargeMacaroon(thirdPartyKey, caveatId, thirdPartyLocation, verifierMock.Object);

			var ipCaveat = new FirstPartyCaveat("ip = 192.0.10.168");
			var expCaveat = new FirstPartyCaveat("exp = 12345");

			dischargeMacaroon.AddFirstPartyCaveat(ipCaveat);
			dischargeMacaroon.AddFirstPartyCaveat(expCaveat);
			dischargeMacaroon.Finalize();

			var sealedDischargeMacaroons = authorisingMacaroon.PrepareForRequest(new List<Macaroon> { dischargeMacaroon });

			var result = authorisingMacaroon.Validate(sealedDischargeMacaroons, verifierMock.Object, authorisingRootKey);
			Assert.That(result.IsValid, Is.EqualTo(true));
		}

		[Test]
		public void Verify_FirstPartyCaveats_FollowedBy_ThirdPartyCaveat_ValidPredicates_ShouldVerify()
		{
			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			/* Create auth with some first party caveats */
			var authorisingRootKey = KeyGen();
			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(authorisingRootKey);

			var serverCaveat = new FirstPartyCaveat("datacenter = Internal");
			var lanAsAFactorCaveat = new FirstPartyCaveat("lan = true");

			authorisingMacaroon.AddFirstPartyCaveat(serverCaveat);
			authorisingMacaroon.AddFirstPartyCaveat(lanAsAFactorCaveat);

			/* Create third party caveat */
			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var caveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			/* Add it */
			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, caveatRootKey, thirdPartyLocation, thirdPartyKey, out var caveatId);

			var dischargeMacaroon = Macaroon.CreateDischargeMacaroon(thirdPartyKey, caveatId, thirdPartyLocation, verifierMock.Object);

			var ipCaveat = new FirstPartyCaveat("ip = 192.0.10.168");
			var expCaveat = new FirstPartyCaveat("exp = 12345");

			dischargeMacaroon.AddFirstPartyCaveat(ipCaveat);
			dischargeMacaroon.AddFirstPartyCaveat(expCaveat);
			dischargeMacaroon.Finalize();

			var sealedDischargeMacaroons = authorisingMacaroon.PrepareForRequest(new List<Macaroon> { dischargeMacaroon });

			var result = authorisingMacaroon.Validate(sealedDischargeMacaroons, verifierMock.Object, authorisingRootKey);
			Assert.That(result.IsValid, Is.EqualTo(true));
		}

		[Test]
		public void Verify_ThirdPartyCaveat_With_ThirdPartyCaveat_ValidPredicates_ShouldVerify()
		{
			var authorisingRootKey = KeyGen();
			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(authorisingRootKey);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var thirdPartyCaveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, thirdPartyCaveatRootKey, thirdPartyLocation, thirdPartyKey, out var userIdMacaroonCaveatId);
			var userIdDischargeMacaroon = Macaroon.CreateDischargeMacaroon(thirdPartyKey, userIdMacaroonCaveatId, thirdPartyLocation, verifierMock.Object);

			var ipCaveat = new FirstPartyCaveat("ip = 192.0.10.168");
			var expCaveat = new FirstPartyCaveat("exp = 12345");

			userIdDischargeMacaroon.AddFirstPartyCaveat(ipCaveat);
			userIdDischargeMacaroon.AddFirstPartyCaveat(expCaveat);

			/* Create another discharge macaroon and attach it to the above */
			var fourthPartyKey = KeyGen();
			var fourthPartyLocation = "ecris.eu";
			var fourthPartyCaveatRootKey = KeyGen();
			var fourthPartyPredicate = "CriminalRecored = 0";

			userIdDischargeMacaroon.AddThirdPartyCaveat(fourthPartyPredicate, fourthPartyCaveatRootKey, fourthPartyLocation, fourthPartyKey, out var criminalRecoredMacaroonCaveatId);
			var criminalRecordDischargeMacaroon = Macaroon.CreateDischargeMacaroon(fourthPartyKey, criminalRecoredMacaroonCaveatId, fourthPartyLocation, verifierMock.Object);

			/* Finalize the userid discharge since we added last caveat above */
			userIdDischargeMacaroon.Finalize();

			var nationalityCaveat = new FirstPartyCaveat("country = dk");
			var residenceCaveat = new FirstPartyCaveat("residency = dk");

			criminalRecordDischargeMacaroon.AddFirstPartyCaveat(nationalityCaveat);
			criminalRecordDischargeMacaroon.AddFirstPartyCaveat(residenceCaveat);
			criminalRecordDischargeMacaroon.Finalize();

			var sealedDischargeAuthorising = authorisingMacaroon.PrepareForRequest(new List<Macaroon> { userIdDischargeMacaroon });
			var sealedDischargeUserId = userIdDischargeMacaroon.PrepareForRequest(new List<Macaroon> { criminalRecordDischargeMacaroon });

			var sealedDischargeMacaroons = sealedDischargeAuthorising.Concat(sealedDischargeUserId).ToList();

			var result = authorisingMacaroon.Validate(sealedDischargeMacaroons, verifierMock.Object, authorisingRootKey);
			Assert.That(result.IsValid, Is.EqualTo(true));
		}

		[Test]
		public void Verify_AlterDischargeLocation_ShouldNotVerify()
		{
			var authorisingRootKey = KeyGen();
			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(authorisingRootKey);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var caveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, caveatRootKey, thirdPartyLocation, thirdPartyKey, out var caveatId);

			var dischargeMacaroon = Macaroon.CreateDischargeMacaroon(thirdPartyKey, caveatId, thirdPartyLocation, verifierMock.Object);

			var ipCaveat = new FirstPartyCaveat("ip = 192.0.10.168");
			var expCaveat = new FirstPartyCaveat("exp = 12345");

			dischargeMacaroon.AddFirstPartyCaveat(ipCaveat);
			dischargeMacaroon.AddFirstPartyCaveat(expCaveat);
			dischargeMacaroon.Finalize();

			var sealedDischargeMacaroons = authorisingMacaroon.PrepareForRequest(new List<Macaroon> { dischargeMacaroon });

			/* Alter Location which is aad */
			sealedDischargeMacaroons.ForEach(x => x.Location += "Wrong");

			var result = authorisingMacaroon.Validate(sealedDischargeMacaroons, verifierMock.Object, authorisingRootKey);
			Assert.That(result.IsValid, Is.EqualTo(false));
			Assert.That(result.MacaroonValidationException, Is.InstanceOf<MacaroonAuthenticityException>());
		}

		[Test]
		public void Verify_MissingDischarge_ShouldNotVerify()
		{
			var authorisingRootKey = KeyGen();
			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(authorisingRootKey);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var caveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, caveatRootKey, thirdPartyLocation, thirdPartyKey, out var caveatId);

			var dischargeMacaroon = Macaroon.CreateDischargeMacaroon(thirdPartyKey, caveatId, thirdPartyLocation, verifierMock.Object);

			var ipCaveat = new FirstPartyCaveat("ip = 192.0.10.168");
			var expCaveat = new FirstPartyCaveat("exp = 12345");

			dischargeMacaroon.AddFirstPartyCaveat(ipCaveat);
			dischargeMacaroon.AddFirstPartyCaveat(expCaveat);
			dischargeMacaroon.Finalize();

			var sealedDischargeMacaroons = authorisingMacaroon.PrepareForRequest(new List<Macaroon> { dischargeMacaroon });

			/* Send in empty list, so we wont find discharge */
			var result = authorisingMacaroon.Validate(new List<Macaroon>(), verifierMock.Object, authorisingRootKey);
			Assert.That(result.IsValid, Is.EqualTo(false));
			Assert.That(result.MacaroonValidationException, Is.InstanceOf<DischargeMacaroonNotFoundException>());
		}

		#endregion

		#region Serialization

		[Test]
		public void Serialize_Then_Deserialize_ShouldVerify()
		{
			var rootKey = KeyGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(rootKey);

			var adminCaveat = new FirstPartyCaveat("user == admin");
			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat);

			var notbeforeCaveat = new FirstPartyCaveat("nbf 1641223209");
			authorisingMacaroon.AddFirstPartyCaveat(notbeforeCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var caveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, caveatRootKey, thirdPartyLocation, thirdPartyKey, out var caveatId);

			var dischargeMacaroon = Macaroon.CreateDischargeMacaroon(thirdPartyKey, caveatId, thirdPartyLocation, verifierMock.Object);

			var ipCaveat = new FirstPartyCaveat("ip = 192.0.10.168");
			var expCaveat = new FirstPartyCaveat("exp = 12345");

			dischargeMacaroon.AddFirstPartyCaveat(ipCaveat);
			dischargeMacaroon.AddFirstPartyCaveat(expCaveat);
			dischargeMacaroon.Finalize();

			var sealedDischargeMacaroon = authorisingMacaroon.PrepareForRequest(new List<Macaroon> { dischargeMacaroon }).First();

			var authorizingSerialized = authorisingMacaroon.Serialize();
			var dischargeSerialized = sealedDischargeMacaroon.Serialize();

			var deserializedAuthorizing = Macaroon.Deserialize(authorizingSerialized, isDischarge: false);
			var deserializedDischarge = Macaroon.Deserialize(dischargeSerialized, isDischarge: true);

			var validationResult = deserializedAuthorizing.Validate(new List<Macaroon> { deserializedDischarge }, verifierMock.Object, rootKey);
			Assert.That(validationResult.IsValid, Is.True);
		}

		[Test]
		public void Deserialize_AuthorisingMacaroonCaveatAltered_ShouldNotVerify()
		{
			var rootKey = KeyGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(rootKey);

			var adminCaveat = new FirstPartyCaveat("user == admin");
			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat);

			var notbeforeCaveat = new FirstPartyCaveat("nbf 1641223209");
			authorisingMacaroon.AddFirstPartyCaveat(notbeforeCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var caveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, caveatRootKey, thirdPartyLocation, thirdPartyKey, out var caveatId);

			var dischargeMacaroon = Macaroon.CreateDischargeMacaroon(thirdPartyKey, caveatId, thirdPartyLocation, verifierMock.Object);

			var ipCaveat = new FirstPartyCaveat("ip = 192.0.10.168");
			var expCaveat = new FirstPartyCaveat("exp = 12345");

			dischargeMacaroon.AddFirstPartyCaveat(ipCaveat);
			dischargeMacaroon.AddFirstPartyCaveat(expCaveat);
			dischargeMacaroon.Finalize();

			var sealedDischargeMacaroon = authorisingMacaroon.PrepareForRequest(new List<Macaroon> { dischargeMacaroon }).First();

			var authorizingJson = Encode.DefaultStringEncoder(Encode.Base64UrlDecode(authorisingMacaroon.Serialize()));
			var dischargeSerialized = sealedDischargeMacaroon.Serialize();

			authorizingJson = authorizingJson.Replace("user == admin", "user == anon"); // Alter a caveat

			var deserializedAuthorizing = Macaroon.Deserialize(Encode.Base64UrlEncode(Encode.DefaultStringDecoder(authorizingJson)), isDischarge: false);
			var deserializedDischarge = Macaroon.Deserialize(dischargeSerialized, isDischarge: true);

			var validationResult = deserializedAuthorizing.Validate(new List<Macaroon> { deserializedDischarge }, verifierMock.Object, rootKey);
			Assert.That(validationResult.IsValid, Is.False);
			Assert.That(validationResult.MacaroonValidationException, Is.InstanceOf<MacaroonAuthenticityException>());
		}

		[Test]
		public void Deserialize_DischargeMacaroonLocationAltered_ShouldNotVerify()
		{
			var rootKey = KeyGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(rootKey);

			var adminCaveat = new FirstPartyCaveat("user == admin");
			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat);

			var notbeforeCaveat = new FirstPartyCaveat("nbf 1641223209");
			authorisingMacaroon.AddFirstPartyCaveat(notbeforeCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var caveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, caveatRootKey, thirdPartyLocation, thirdPartyKey, out var caveatId);

			var dischargeMacaroon = Macaroon.CreateDischargeMacaroon(thirdPartyKey, caveatId, thirdPartyLocation, verifierMock.Object);

			var ipCaveat = new FirstPartyCaveat("ip = 192.0.10.168");
			var expCaveat = new FirstPartyCaveat("exp = 12345");

			dischargeMacaroon.AddFirstPartyCaveat(ipCaveat);
			dischargeMacaroon.AddFirstPartyCaveat(expCaveat);
			dischargeMacaroon.Finalize();

			var sealedDischargeMacaroon = authorisingMacaroon.PrepareForRequest(new List<Macaroon> { dischargeMacaroon }).First();

			var authorizingSerialized = authorisingMacaroon.Serialize();
			var dischargeJson = Encode.DefaultStringEncoder(Encode.Base64UrlDecode(sealedDischargeMacaroon.Serialize()));

			dischargeJson = dischargeJson.Replace("https://example.com", "https://myevildomain.com"); // Alter location. It is part of aad for third party caveats. But only in the discharge itself.

			var deserializedAuthorizing = Macaroon.Deserialize(authorizingSerialized, isDischarge: false);
			var deserializedDischarge = Macaroon.Deserialize(Encode.Base64UrlEncode(Encode.DefaultStringDecoder(dischargeJson)), isDischarge: true);

			var validationResult = deserializedAuthorizing.Validate(new List<Macaroon> { deserializedDischarge }, verifierMock.Object, rootKey);
			Assert.That(validationResult.IsValid, Is.False);
			Assert.That(validationResult.MacaroonValidationException, Is.InstanceOf<MacaroonAuthenticityException>());
		}

		[Test]
		public void Deserialize_DischargeMacaroonCaveatAltered_ShouldNotVerify()
		{
			var rootKey = KeyGen();

			var authorisingMacaroon = Macaroon.CreateAuthorisingMacaroon(rootKey);

			var adminCaveat = new FirstPartyCaveat("user == admin");
			authorisingMacaroon.AddFirstPartyCaveat(adminCaveat);

			var notbeforeCaveat = new FirstPartyCaveat("nbf 1641223209");
			authorisingMacaroon.AddFirstPartyCaveat(notbeforeCaveat);

			var verifierMock = new Mock<IPredicateVerifier>();
			verifierMock.Setup(x => x.Verify(It.IsAny<string>())).Returns(true);

			var thirdPartyKey = KeyGen(); /* This would be a general key exchanged with third party */
			var thirdPartyLocation = "https://example.com";
			var caveatRootKey = KeyGen(); /* Key specific to this caveat that we encrypt in the caveat to make it self-contained */
			var thirdPartyPredicate = "userID = 1234567890";

			authorisingMacaroon.AddThirdPartyCaveat(thirdPartyPredicate, caveatRootKey, thirdPartyLocation, thirdPartyKey, out var caveatId);

			var dischargeMacaroon = Macaroon.CreateDischargeMacaroon(thirdPartyKey, caveatId, thirdPartyLocation, verifierMock.Object);

			var ipCaveat = new FirstPartyCaveat("ip = 192.0.10.168");
			var expCaveat = new FirstPartyCaveat("exp = 12345");

			dischargeMacaroon.AddFirstPartyCaveat(ipCaveat);
			dischargeMacaroon.AddFirstPartyCaveat(expCaveat);
			dischargeMacaroon.Finalize();

			var sealedDischargeMacaroon = authorisingMacaroon.PrepareForRequest(new List<Macaroon> { dischargeMacaroon }).First();

			var authorizingSerialized = authorisingMacaroon.Serialize();
			var dischargeJson = Encode.DefaultStringEncoder(Encode.Base64UrlDecode(sealedDischargeMacaroon.Serialize()));

			dischargeJson = dischargeJson.Replace("exp = 12345", "exp = 99999");

			var deserializedAuthorizing = Macaroon.Deserialize(authorizingSerialized, isDischarge: false);
			var deserializedDischarge = Macaroon.Deserialize(Encode.Base64UrlEncode(Encode.DefaultStringDecoder(dischargeJson)), isDischarge: true);

			var validationResult = deserializedAuthorizing.Validate(new List<Macaroon> { deserializedDischarge }, verifierMock.Object, rootKey);
			Assert.That(validationResult.IsValid, Is.False);
			Assert.That(validationResult.MacaroonValidationException, Is.InstanceOf<MacaroonAuthenticityException>());
		}

		[Test]
		public void Deserialize_MissingId_ShouldThrow()
		{
			var serializedMissingId = @"{
    ""Location"": null,
    ""Caveats"": [{
        ""Location"": null,
        ""CaveatId"": ""user == admin"",
        ""VerificationId"": ""0""
    },
    {
        ""Location"": null,
        ""CaveatId"": ""nbf 1641223209"",
        ""VerificationId"": ""0""
    },
    {
        ""Location"": ""https://example.com"",
        ""CaveatId"": ""MDWA8kqxfTtBoPmQ0bKM0HIZsIYcpFoLJvj3UXIj76Tp0nMgd69CQuLOl8QrN/ISeI4YAvWWUjDrxc3gwGeG\u002BWa\u002BoT5v20x6bQlQYmdUgw=="",
        ""VerificationId"": ""RWmTBRv4INxcHuJOfE\u002BtryjggvZebA0F87pmE4H3uqMT0xVHGDZU8FbVyhelbLoRgdCiayOnlwo9dGXO""
    }],
    ""Signature"": ""1JH5wR2UoiNwKXqdlsI1375B6CBdnLWoOzC3FvUFNew=""
}"
;
			//TODO: check on the exception message to assert we threw the right place. 
			Assert.Throws<MacaroonDeserializationException>(() => Macaroon.Deserialize(Encode.Base64UrlEncode(Encode.DefaultStringDecoder(serializedMissingId)), isDischarge: false));
		}

		[Test]
		public void Deserialize_MissingSignature_ShouldThrow()
		{
			var serializedMissingSignature = @"{
    ""Location"": ""https://example.com"",
    ""Id"": ""MDWA8kqxfTtBoPmQ0bKM0HIZsIYcpFoLJvj3UXIj76Tp0nMgd69CQuLOl8QrN/ISeI4YAvWWUjDrxc3gwGeG\u002BWa\u002BoT5v20x6bQlQYmdUgw=="",
    ""Caveats"": [{
        ""Location"": null,
        ""CaveatId"": ""ip = 192.0.10.168"",
        ""VerificationId"": ""0""
    },
    {
        ""Location"": null,
        ""CaveatId"": ""exp = 12345"",
        ""VerificationId"": ""0""
    }],
}"
;
			//TODO: check on the exception message to assert we threw the right place. 
			Assert.Throws<MacaroonDeserializationException>(() => Macaroon.Deserialize(Encode.Base64UrlEncode(Encode.DefaultStringDecoder(serializedMissingSignature)), isDischarge: false));
		}

		[Test]
		public void Deserialize_FirstPartyCaveatMissingCaveatId_ShouldThrow()
		{
			var serializedMissingFirstPartyCaveatId = @"{
    ""Location"": ""https://example.com"",
    ""Id"": ""MDWA8kqxfTtBoPmQ0bKM0HIZsIYcpFoLJvj3UXIj76Tp0nMgd69CQuLOl8QrN/ISeI4YAvWWUjDrxc3gwGeG\u002BWa\u002BoT5v20x6bQlQYmdUgw=="",
    ""Caveats"": [{
        ""Location"": null,
        ""VerificationId"": ""0""
    },
    {
        ""Location"": null,
        ""CaveatId"": ""exp = 12345"",
        ""VerificationId"": ""0""
    }],
    ""Signature"": ""Tpg/PBfxKnQyjW1jsLUq7MCmTHClJVYgK8ttCVJhBdw=""
}"
;
			//TODO: check on the exception message to assert we threw the right place. 
			Assert.Throws<MacaroonDeserializationException>(() => Macaroon.Deserialize(Encode.Base64UrlEncode(Encode.DefaultStringDecoder(serializedMissingFirstPartyCaveatId)), isDischarge: false));
		}

		[Test]
		public void Deserialize_FirstPartyCaveatMissingVerificationId_ShouldThrow()
		{
			var serializedMissingFirstPatyCaveatVerificationID = @"{
    ""Location"": ""https://example.com"",
    ""Id"": ""MDWA8kqxfTtBoPmQ0bKM0HIZsIYcpFoLJvj3UXIj76Tp0nMgd69CQuLOl8QrN/ISeI4YAvWWUjDrxc3gwGeG\u002BWa\u002BoT5v20x6bQlQYmdUgw=="",
    ""Caveats"": [{
        ""Location"": null,
        ""CaveatId"": ""ip = 192.0.10.168"",
    },
    {
        ""Location"": null,
        ""CaveatId"": ""exp = 12345"",
        ""VerificationId"": ""0""
    }],
    ""Signature"": ""Tpg/PBfxKnQyjW1jsLUq7MCmTHClJVYgK8ttCVJhBdw=""
}"
;
			//TODO: check on the exception message to assert we threw the right place. 
			Assert.Throws<MacaroonDeserializationException>(() => Macaroon.Deserialize(Encode.Base64UrlEncode(Encode.DefaultStringDecoder(serializedMissingFirstPatyCaveatVerificationID)), isDischarge: false));
		}

		[Test]
		public void Deserialize_ThirdPartyCaveatMissingCaveatId_ShouldThrow()
		{
			var serializedMissingThirdPartyCaveatId = @"{
    ""Location"": null,
    ""Id"": ""0jRladhaS4\u002B0gU59pYgXfQn4nLFnmUpdzBoUNxKfdOo="",
    ""Caveats"": [{
        ""Location"": null,
        ""CaveatId"": ""user == admin"",
        ""VerificationId"": ""0""
    },
    {
        ""Location"": null,
        ""CaveatId"": ""nbf 1641223209"",
        ""VerificationId"": ""0""
    },
    {
        ""Location"": ""https://example.com"",
        ""VerificationId"": ""RWmTBRv4INxcHuJOfE\u002BtryjggvZebA0F87pmE4H3uqMT0xVHGDZU8FbVyhelbLoRgdCiayOnlwo9dGXO""
    }],
    ""Signature"": ""1JH5wR2UoiNwKXqdlsI1375B6CBdnLWoOzC3FvUFNew=""
}"
;
			//TODO: check on the exception message to assert we threw the right place. 
			Assert.Throws<MacaroonDeserializationException>(() => Macaroon.Deserialize(Encode.Base64UrlEncode(Encode.DefaultStringDecoder(serializedMissingThirdPartyCaveatId)), isDischarge: false));
		}

		[Test]
		public void Deserialize_ThirdPartyCaveatMissingVerificationId_ShouldThrow()
		{
			var serializedMissingThirdPartyCaveatVerificationId = @"{
    ""Location"": null,
    ""Id"": ""0jRladhaS4\u002B0gU59pYgXfQn4nLFnmUpdzBoUNxKfdOo="",
    ""Caveats"": [{
        ""Location"": null,
        ""CaveatId"": ""user == admin"",
        ""VerificationId"": ""0""
    },
    {
        ""Location"": null,
        ""CaveatId"": ""nbf 1641223209"",
        ""VerificationId"": ""0""
    },
    {
        ""Location"": ""https://example.com"",
        ""CaveatId"": ""MDWA8kqxfTtBoPmQ0bKM0HIZsIYcpFoLJvj3UXIj76Tp0nMgd69CQuLOl8QrN/ISeI4YAvWWUjDrxc3gwGeG\u002BWa\u002BoT5v20x6bQlQYmdUgw=="",
    }],
    ""Signature"": ""1JH5wR2UoiNwKXqdlsI1375B6CBdnLWoOzC3FvUFNew=""
}"
;
			//TODO: check on the exception message to assert we threw the right place. 
			Assert.Throws<MacaroonDeserializationException>(() => Macaroon.Deserialize(Encode.Base64UrlEncode(Encode.DefaultStringDecoder(serializedMissingThirdPartyCaveatVerificationId)), isDischarge: false));
		}

		#endregion Serialization


		#region Helpers

		private byte[] KeyGen()
		{
			var csprng = RandomNumberGenerator.Create();
			var key = new byte[SymmetricCryptography.AesKeySizeInBytes];
			csprng.GetBytes(key);
			return key;
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
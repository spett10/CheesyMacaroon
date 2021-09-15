using MacaroonCore;
using NUnit.Framework;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace MacaroonCoreTests
{
	public class TimeConstantUtilityTests
	{
		[Test]
		public void TimeConstantCompare_NotEqual_ShouldReturnFalse()
		{
			var csprng = RandomNumberGenerator.Create();
			var left = new byte[32];
			var right = new byte[32];

			csprng.GetBytes(left);
			csprng.GetBytes(right);

			Assert.That(left.TimeConstantCompare(right), Is.EqualTo(false));
		}

		[Test]
		public void TimeConstantCompare_Equal_ShouldReturnFalse()
		{
			var csprng = RandomNumberGenerator.Create();
			var left = new byte[32];
			var right = new byte[32];

			csprng.GetBytes(left);

			Array.Copy(left, right, left.Length);


			Assert.That(left.TimeConstantCompare(right), Is.EqualTo(true));
		}

		[Test]
		public void TimeConstantCompare_NotSameLength_ShouldReturnFalse()
		{
			var csprng = RandomNumberGenerator.Create();
			var left = new byte[32];
			var right = new byte[32];

			csprng.GetBytes(left);

			Array.Copy(left, right, left.Length);
			right = right.Take(20).ToArray();

			Assert.That(left.TimeConstantCompare(right), Is.EqualTo(false));
		}
	}
}

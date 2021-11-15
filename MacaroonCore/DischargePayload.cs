using System.Linq;

namespace MacaroonCore
{
	internal class DischargePayload
	{
		byte[] _payload;

		public DischargePayload(byte[] payload)
		{
			_payload = payload;
		}

		public byte[] RootKey { get { return _payload.Take(SymmetricCryptography.AesKeySizeInBytes).ToArray(); } }
		public byte[] Predicate { get { return _payload.Skip(SymmetricCryptography.AesKeySizeInBytes).ToArray(); } }
	}
}

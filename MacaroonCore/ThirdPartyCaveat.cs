using System;
using System.Collections.Generic;

namespace MacaroonCore
{
	public class ThirdPartyCaveat : Caveat
	{
		public ThirdPartyCaveat(List<string> predicates, byte[] caveatRootKey)
		{

		}

		public override byte[] Payload()
		{
			throw new NotImplementedException();
		}
	}
}

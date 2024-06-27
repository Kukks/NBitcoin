#if HAS_SPAN
using System;
using System.Collections.Generic;
using System.Linq;

namespace NBitcoin.Secp256k1
{
#if SECP256K1_LIB
	public
#endif
	class Pederson
	{
		public static void CommitmentLoad(ref GE ge, in byte[] commit)
		{
			var fe = new FE(commit.AsSpan(1));
			var GE = new GE(fe,new FE());
			ge.SetXQuad(ref fe);
			if ((commit[0] & 1) != 0)
			{
				ge.Negate();
			}
		}
		 static Scalar secp256k1_pedersen_scalar_set_u64(ulong value)
		{
			byte[] data = new byte[32];
			int i;
			for (i = 0; i < 24; i++)
			{
				data[i] = 0;
			}
			for (; i < 32; i++)
			{
				data[i] = (byte)(value >> 56);
				value <<= 8;
			}
			return  new Scalar(data, out _);
		}

		 public static GEJ secp256k1_pedersen_ecmult_small(ulong gn, in GE genp)
		{
			var s = secp256k1_pedersen_scalar_set_u64( gn);
			return genp.MultConst(s, 64);
		}

		/* sec * G + value * G2. */
		public static GEJ secp256k1_pedersen_ecmult(in Scalar sec, ulong value, in GE genp)
		{
			var rj = Context.Instance.EcMultGenContext.MultGen(sec);
			var vj = secp256k1_pedersen_ecmult_small( value, in genp);
			/* FIXME: constant time. */
			return  rj.Add(vj.ToGroupElement());
		}
	}
}
#endif

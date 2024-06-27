#if HAS_SPAN
using System;
using System.Linq;

namespace NBitcoin.Secp256k1
{
#if SECP256K1_LIB
	public
#endif
		class Borromean
	{
		public static byte[] Hash(byte[] m, byte[] e, uint ridx, uint eidx)
		{
			uint ring = ridx;
			uint epos = eidx;
			using var sha = new SHA256();
			sha.Write(e);
			sha.Write(m);
			sha.Write(BitConverter.GetBytes(ring).Reverse().ToArray());
			sha.Write(BitConverter.GetBytes(epos).Reverse().ToArray());

			return sha.GetHash();
		}

		public static bool Verify(Scalar[] evalues, byte[] e0, Scalar[] s, GEJ[] pubs, int[] rsizes,
			int nrings, byte[] m)
		{
			using SHA256 sha256_e0 = new SHA256();

			if (e0 == null || s == null || pubs == null || rsizes == null || nrings == 0 || m == null)
				return false;

			int count = 0;
			sha256_e0.Initialize();

			for (uint i = 0; i < nrings; i++)
			{
				if (int.MaxValue - count <= rsizes[i])
					return false;

				var hash = Hash(m,  e0, i, 0);
				if (hash.Length > 32)
				{
					return false;
				}

				var ens = new Scalar(hash);

				for (uint j = 0; j < rsizes[i]; j++)
				{
					if (s[count].IsZero || ens.IsZero || pubs[count].IsInfinity)
						return false;

					if (evalues != null)
						evalues[count] = ens;

					Scalar? lastS = s[count];
					var rgej = Context.Instance.EcMultContext.Mult(in pubs[count], in ens, in lastS);

					if (rgej.IsInfinity)
						return false;
					var rge = rgej.ToGroupElement();
					var serializedRge = new byte[33];
					ECPubKey.secp256k1_eckey_pubkey_serialize(serializedRge, ref rge, out _, true);

					if (j != rsizes[i] - 1)
					{
						ens = new Scalar(Hash(m,  serializedRge, i,  (j + 1)));
					}
					else
					{
						sha256_e0.Write(serializedRge);
					}

					count++;
				}
			}

			var hashResult = sha256_e0.GetHash();

			return ECPubKey.secp256k1_memcmp_var(e0, hashResult, 32) == 0;
		}

		public static bool Sign(byte[] e0, Scalar[] s, GEJ[] pubs, Scalar[] k, Scalar[] sec, int[] rsizes,
			uint[] secidx, int nrings, byte[] m)
		{
			GEJ rgej = new GEJ();
			GE rge = new GE();
			Scalar ens = new Scalar();
			int count;
			byte[] hashResult;
			using SHA256 sha256_e0 = new SHA256();

			if (e0 == null || s == null || pubs == null || k == null || sec == null || rsizes == null ||
			    secidx == null || nrings == 0 || m == null)
				return false;

			sha256_e0.Initialize();
			count = 0;

			for (uint i = 0; i < nrings; i++)
			{
				if ((int.MaxValue - count) <= rsizes[i])
					return false;

				rgej = ECMultGenContext.Instance.MultGen(k[i]);
				rge = rgej.ToGroupElement();
				if (rgej.IsInfinity)
					return false;

				byte[] serializedRge = new byte[33];
				ECPubKey.secp256k1_eckey_pubkey_serialize(serializedRge, ref rge, out _, true);

				for (uint j = secidx[i] + 1; j < rsizes[i]; j++)
				{
					var tmp = Hash(m,  serializedRge, i,  j);
					ens = new Scalar(tmp);

					if (ens.IsZero)
						return false;

					rgej = Context.Instance.EcMultContext.Mult(pubs[count + j], ens, s[count + j]);

					if (rgej.IsInfinity)
						return false;

					rge = rgej.ToGroupElement();
					ECPubKey.secp256k1_eckey_pubkey_serialize(serializedRge, ref rge, out _, true);
				}

				sha256_e0.Write(serializedRge);
				count += rsizes[i];
			}

			hashResult = sha256_e0.GetHash();

			Buffer.BlockCopy(hashResult, 0, e0, 0, 32);

			count = 0;

			for (uint i = 0; i < nrings; i++)
			{
				if (int.MaxValue - count <= rsizes[i])
					return false;

				ens = new Scalar(Hash(m, e0, i, 0));
				if (ens.IsZero)
					return false;

				for (uint j = 0; j < secidx[i]; j++)
				{
					rgej = Context.Instance.EcMultContext.Mult(pubs[count + j], ens, s[count + j]);

					if (rgej.IsInfinity)
						return false;

					rge = rgej.ToGroupElement();
					var serializedRge = new byte[33];
					ECPubKey.secp256k1_eckey_pubkey_serialize(serializedRge, ref rge, out _, true);

					ens = new Scalar(Hash(m,  serializedRge,  i, j + 1));
					if (ens.IsZero)
						return false;
				}

				s[count + secidx[i]] = ens.Multiply(sec[i]);
				s[count + secidx[i]] = s[count + secidx[i]].Negate();
				s[count + secidx[i]] = s[count + secidx[i]].Add(k[i]);

				if (s[count + secidx[i]].IsZero)
					return false;

				count += rsizes[i];
			}

			return true;
		}

	}
}
#endif

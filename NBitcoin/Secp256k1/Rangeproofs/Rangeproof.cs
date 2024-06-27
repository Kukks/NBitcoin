#if HAS_SPAN
using System;
using System.Collections.Generic;
using System.Linq;

namespace NBitcoin.Secp256k1
{
#if SECP256K1_LIB
	public
#endif
		class Rangeproof
	{
		public static void secp256k1_rangeproof_pub_expand(GEJ[] pubs, int exp, int[] rsizes, int rings, in GE genp)
		{
			GEJ basej;
			GEJ tmp = new();
			uint i, j;
			uint npub;

			if (!(exp < 19))
			{
				return;
			}

			if (exp < 0)
			{
				exp = 0;
			}

			basej = genp.ToGroupElementJacobian();
			basej = basej.Negate();

			while (exp-- > 0)
			{
				tmp = basej.Double();
				basej = tmp.Double().Double().Add(tmp.ToGroupElement());
			}

			npub = 0;
			for (i = 0; i < rings; i++)
			{
				for (j = 1; j < rsizes[i]; j++)
				{
					pubs[npub + j] = pubs[npub + j - 1].Add(basej.ToGroupElement());
				}

				if (i < rings - 1)
				{
					basej = basej.Double();
					basej = basej.Double();
				}

				npub = (uint) (npub + rsizes[i]);
			}
		}

		public static byte[] secp256k1_rangeproof_serialize_point(in GE point)
		{
			var pointx = point.x;
			pointx = pointx.Normalize();
			var res = new List<byte> {(byte) (point.y.IsQuadVariable ? 0 : 1)};
			res.AddRange(pointx.ToBytes());
			return res.ToArray();
		}

		public static bool secp256k1_rangeproof_genrand(Scalar[] sec, Scalar[] s, byte[] message,
			int[] rsizes, int rings, byte[] nonce, in GE commit, byte[] proof, uint len, in GE genp)
		{
			byte[] tmp = new byte[32];
			byte[] rngseed = new byte[32 + 33 + 33 + 10];
			using RFC6979HMACSHA256 rng = new RFC6979HMACSHA256();
			Scalar acc = new Scalar();
			uint i, j;
			ulong b;
			uint npub;

			if (!(len <= 10))
			{
				return false;
			}

			Array.Copy(nonce, 0, rngseed, 0, 32);
			rngseed = secp256k1_rangeproof_serialize_point(commit).Concat(secp256k1_rangeproof_serialize_point(genp))
				.Concat(proof).ToArray();
			rng.Initialize(rngseed);

			npub = 0;
			var ret = true;
			for (i = 0; i < rings; i++)
			{
				if (i < rings - 1)
				{
					do
					{
						rng.Generate(tmp);
						sec[i] = new Scalar(tmp);
					} while (sec[i].CheckOverflow() > 0 && sec[i].IsZero);

					acc = acc.Add(sec[i]);
				}
				else
				{
					acc = acc.Negate();
					sec[i] = acc;
				}

				for (j = 0; j < rsizes[i]; j++)
				{
					rng.Generate(tmp);

					if (message != null)
					{
						for (b = 0; b < 32; b++)
						{
							tmp[b] ^= message[(int) ((i * 4 + j) * 32 + b)];
							message[(int) ((i * 4 + j) * 32 + b)] = tmp[b];
						}
					}

					s[npub] = new Scalar(tmp);

					ret &= !(s[npub].CheckOverflow() > 0 || s[npub].IsZero);
					npub++;
				}
			}

			return true;
		}

		public static int secp256k1_clz64_var(ulong x)
		{
			int ret;

			if (x == 0)
			{
				return 64;
			}

			ret = 0;

			while ((x & 0x8000000000000000) == 0)
			{
				x <<= 1;
				ret++;
			}

			return ret;
		}

		static bool secp256k1_range_proveparams(out ulong v, out int rings, int[] rsizes, out uint npub,
			uint[] secidx, ref ulong min_value,
			ref int mantissa, ref ulong scale, ref int exp, ref int min_bits, ulong value)
		{
			v = 0;
			uint i;
			rings = 1;
			rsizes[0] = 1;
			secidx[0] = 0;
			scale = 1;
			mantissa = 0;
			npub = 0;

			if (min_value == ulong.MaxValue)
			{
				// If the minimum value is the maximal representable value, then we cannot code a range.
				exp = -1;
			}

			if (exp >= 0)
			{
				int max_bits;
				ulong v2;

				if ((min_value != 0 && value > long.MaxValue) || (value != 0 && min_value >= long.MaxValue))
				{
					// If either value or min_value is >= 2^63-1 then the other must be zero to avoid overflowing the proven range.
					return false;
				}

				max_bits = (min_value != 0) ? secp256k1_clz64_var(min_value) : 64;

				if (min_bits > max_bits)
				{
					min_bits = max_bits;
				}

				if (min_bits > 61 || value > long.MaxValue)
				{
					// Ten is not a power of two, so dividing by ten and then representing in base-2 times ten expands the representable range.
					// The verifier requires the proven range to be within 0..2^64. For very large numbers (all over 2^63), we must change our exponent to compensate.
					// Rather than handling it precisely, this just disables the use of the exponent for big values.
					exp = 0;
				}

				// Mask off the least significant digits, as requested.
				v = (value - min_value);

				// If the user has asked for more bits of proof than there is room for in the exponent, reduce the exponent.
				v2 = (min_bits != 0) ? (ulong.MaxValue >> 64 - min_bits) : 0;

				for (i = 0; i < exp && (v2 <= ulong.MaxValue / 10); i++)
				{
					v /= 10;
					v2 *= 10;
				}

				exp = (int) i;
				v2 = v;

				for (i = 0; i < exp; i++)
				{
					v2 *= 10;
					scale *= 10;
				}

				// If the masked number isn't precise, compute the public offset.
				min_value = value - v2;

				// How many bits do we need to represent our value?
				mantissa = (v != 0) ? 64 - secp256k1_clz64_var(v) : 1;

				if (min_bits > mantissa)
				{
					// If the user asked for more precision, give it to them.
					mantissa = min_bits;
				}

				// Digits in radix-4, except for the last digit if our mantissa length is odd.
				rings = ((mantissa + 1) >> 1);

				for (i = 0; i < rings; i++)
				{
					rsizes[i] = ((i < rings - 1) | ((mantissa & 1) == 0) ? 4 : 2);
					npub = (uint) (npub + rsizes[i]);
					secidx[i] = (uint) ((v >> (int) (i * 2)) & 3);
				}

				if (!(mantissa > 0))
				{
					return false;
				}

				if ((v & ~(ulong.MaxValue >> (64 - mantissa))) != 0)
				{
					return false;
				}
			}
			else
			{
				// A proof for an exact value.
				exp = 0;
				min_value = value;
				v = 0;
				npub = 2;
			}

			return (v * scale + min_value == value) && (rings > 0) && (rings <= 32) && (npub <= 128);
		}

		public static bool secp256k1_rangeproof_sign_impl(ref byte[] proof, ref int plen, ulong min_value,
			GE commit, byte[] blind, byte[] nonce, int exp, int min_bits, ulong value,
			byte[] message, int msg_len, byte[] extra_commit, GE genp)
		{
			GEJ[] pubs = new GEJ[128];
			Scalar[] s = new Scalar[128];
			Scalar[] sec = new Scalar[32];
			Scalar[] k = new Scalar[32];
			Scalar stmp = default(Scalar);
			var sha256_m = new SHA256();
			byte[] prep = new byte[4096];
			byte[] tmp = new byte[33];
			byte[] signs; // Location of sign flags in the proof.
			ulong v;
			ulong scale = 0; // scale = 10^exp.
			int mantissa = 0; // Number of bits proven in the blinded value.
			int rings; // How many digits will our proof cover.
			int[] rsizes = new int[32]; // How many possible values there are for each place.
			uint[] secidx = new uint[32]; // Which digit is the correct one.
			uint len = 0;
			int i;
			uint npub;

			len = 0;
			if (plen < 65 || min_value > value || min_bits > 64 || min_bits < 0 || exp < -1 || exp > 18)
			{
				return false;
			}

			if (!secp256k1_range_proveparams(out v, out rings, rsizes, out npub, secidx, ref min_value, ref mantissa,
				    ref scale, ref exp, ref min_bits, value))
			{
				return false;
			}

			proof[len] = (byte) ((rsizes[0] > 1 ? (64 | exp) : 0) | (min_value != 0 ? 32 : 0));
			len++;
			if (rsizes[0] > 1)
			{
				if (!(mantissa > 0 && mantissa <= 64))
				{
					throw new Exception("Invalid mantissa value.");
				}

				proof[len] = (byte) (mantissa - 1);
				len++;
			}

			if (min_value != 0)
			{
				for (i = 0; i < 8; i++)
				{
					proof[len + i] = (byte) ((min_value >> ((7 - i) * 8)) & 255);
				}

				len += 8;
			}

			if (msg_len > 0 && msg_len > 128 * (rings - 1))
			{
				return false;
			}

			if (plen - len < 32 * (npub + rings - 1) + 32 + ((rings + 6) >> 3))
			{
				return false;
			}

			sha256_m.Initialize();
			sha256_m.Write(secp256k1_rangeproof_serialize_point(commit));
			sha256_m.Write(secp256k1_rangeproof_serialize_point(genp));
			sha256_m.Write(proof);

			Array.Clear(prep, 0, 4096);
			if (message != null)
			{
				Array.Copy(message, prep, msg_len);
			}

			if (rsizes[rings - 1] > 1)
			{
				uint idx;
				idx = (uint) (rsizes[rings - 1] - 1);
				idx = (uint) (idx - (secidx[rings - 1] == idx ? 1 : 0));
				idx = (uint) (((rings - 1) * 4 + idx) * 32);
				for (i = 0; i < 8; i++)
				{
					prep[8 + i + idx] = prep[16 + i + idx] = prep[24 + i + idx] = (byte) ((v >> (56 - i * 8)) & 255);
					prep[i + idx] = 0;
				}

				prep[idx] = 128;
			}

			if (!secp256k1_rangeproof_genrand(sec, s, prep, rsizes, rings, nonce, commit, proof, len, genp))
			{
				return false;
			}

			Array.Clear(prep, 0, 4096);
			for (i = 0; i < rings; i++)
			{
				k[i] = s[i * 4 + secidx[i]];
				s[i * 4 + secidx[i]] = new Scalar();
			}

			stmp = new Scalar(blind);
			sec[rings - 1].Add(stmp);
			if (stmp.CheckOverflow() != 0 || sec[rings - 1].IsZero)
			{
				return false;
			}

			signs = new byte[(rings + 6) >> 3];
			for (i = 0; i < (rings + 6) >> 3; i++)
			{
				signs[i] = 0;
				len++;
			}

			npub = 0;
			for (i = 0; i < rings; i++)
			{
				pubs[npub] = Pederson.secp256k1_pedersen_ecmult(sec[i], (secidx[i] * scale) << (i * 2), genp);
				if (pubs[npub].IsInfinity)
				{
					return false;
				}

				if (i < rings - 1)
				{
					GE c = pubs[npub].ToGroupElement();
					byte quadness;
					var tmpc = secp256k1_rangeproof_serialize_point(c);
					quadness = tmpc[0];
					sha256_m.Write(tmpc);
					signs[i >> 3] |= (byte) (quadness << (i & 7));
					Array.Copy(tmpc, 1, proof, len, 32);
					len += 32;
				}

				npub = (uint) (npub + rsizes[i]);
			}

			secp256k1_rangeproof_pub_expand(pubs, exp, rsizes, rings, genp);
			if (extra_commit != null)
			{
				sha256_m.Write(extra_commit);
			}

			byte[] tmpHash = sha256_m.GetHash();
			byte[] tmpHashTruncated = new byte[32];
			Array.Copy(tmpHash, tmpHashTruncated, 32);
			if (!Borromean.Sign(proof, s, pubs, k, sec, rsizes, secidx, rings, tmpHashTruncated))
			{
				return false;
			}

			len += 32;
			for (i = 0; i < npub; i++)
			{
				s[i].ToBytes().CopyTo(proof, len);
				len += 32;
			}

			if (len > plen)
			{
				return false;
			}

			plen = (int) len;
			Array.Clear(prep, 0, 4096);
			return true;
		}

		internal static byte[] SafeSubarray(byte[] array, uint offset, int count)
		{
			if (array == null)
				throw new ArgumentNullException(nameof(array));
			if (offset < 0 || offset > array.Length)
				throw new ArgumentOutOfRangeException("offset");
			if (count < 0 || offset + count > array.Length)
				throw new ArgumentOutOfRangeException("count");
			if (offset == 0 && array.Length == count)
				return array;
			var data = new byte[count];
			Buffer.BlockCopy(array, (int) offset, data, 0, count);
			return data;
		}

		internal static byte[] SafeSubarray(byte[] array, int offset)
		{
			if (array == null)
				throw new ArgumentNullException(nameof(array));
			if (offset < 0 || offset > array.Length)
				throw new ArgumentOutOfRangeException("offset");

			var count = array.Length - offset;
			var data = new byte[count];
			Buffer.BlockCopy(array, offset, data, 0, count);
			return data;
		}

		static Scalar secp256k1_rangeproof_recover_x(Scalar k, Scalar e, Scalar s)
		{
			return s.Negate().Add(k).Multiply(e.Inverse());
		}

/* Computes ring's nonce given the blinding factor x, the challenge e, and the signature s. */
		static Scalar secp256k1_rangeproof_recover_k(Scalar x, Scalar e, Scalar s)
		{
			var stmp = x.Multiply(e);
			return s.Add(stmp);
		}

		static void secp256k1_rangeproof_ch32xor(byte[] x, byte[] y)
		{
			for (int i = 0; i < 32; i++)
			{
				x[i] ^= y[i];
			}
		}

		public static bool secp256k1_rangeproof_rewind_inner(out Scalar blind, ref ulong v, byte[] m, ref int mlen,
			Scalar[] ev,
			Scalar[] s,
			int[] rsizes, int rings, byte[] nonce, GE commit, byte[] proof, uint len, GE genp)
		{
			Scalar[] s_orig = new Scalar[128];
			Scalar[] sec = new Scalar[32];
			Scalar stmp = new Scalar();
			byte[] prep = new byte[4096];
			byte[] tmp = new byte[32];
			ulong value = 0;
			uint offset;
			uint i;
			uint j;
			int b;
			uint skip1;
			uint skip2;
			int npub;
			blind = default;
			npub = (((rings - 1) << 2) + rsizes[rings - 1]);
			if (npub > 128 || npub < 1)
			{
				return false;
			}

			Array.Clear(prep, 0, prep.Length);
			secp256k1_rangeproof_genrand(sec, s_orig, prep, rsizes, rings, nonce, commit, proof, len, genp);
			v = ulong.MaxValue;
			blind = new Scalar();
			if (rings == 1 && rsizes[0] == 1)
			{
				blind = secp256k1_rangeproof_recover_x(s_orig[0], ev[0], s[0]);
				if (v != null)
				{
					v = 0;
				}

				if (mlen != null)
				{
					mlen = 0;
				}

				return true;
			}

			npub = ((rings - 1) << 2);
			for (j = 0; j < 2; j++)
			{
				uint idx = (uint) (npub + rsizes[rings - 1] - 1 - j);
				tmp = s[idx].ToBytes();
				secp256k1_rangeproof_ch32xor(tmp, SafeSubarray(prep, idx * 32, 32));
				if ((tmp[0] & 128) != 0 &&
				    ECPubKey.secp256k1_memcmp_var(SafeSubarray(tmp, 16, 8), SafeSubarray(tmp, 24, 8), 8) == 0 &&
				    ECPubKey.secp256k1_memcmp_var(SafeSubarray(tmp, 8, 8), SafeSubarray(tmp, 16, 8), 8) == 0)
				{
					value = 0;
					for (i = 0; i < 8; i++)
					{
						value = (value << 8) + tmp[24 + i];
					}

					if (v != null)
					{
						v = value;
					}

					Buffer.BlockCopy(tmp, 0, prep, (int) (idx * 32), 32);
					break;
				}
			}

			if (j > 1)
			{
				if (mlen != null)
				{
					mlen = 0;
				}

				return false;
			}

			skip1 = (uint) (rsizes[rings - 1] - 1 - j);
			skip2 = (uint) ((value >> (int) ((rings - 1) << 1)) & 3);
			if (skip1 == skip2)
			{
				if (mlen != null)
				{
					mlen = 0;
				}

				return false;
			}

			skip1 += (uint) (rings - 1) << 2;
			skip2 += (uint) (rings - 1) << 2;
			stmp = secp256k1_rangeproof_recover_x(s_orig[skip2], ev[skip2], s[skip2]);
			sec[rings - 1] = sec[rings - 1].Negate();
			blind = stmp.Add(sec[rings - 1]);
			if (m == null || mlen == null || mlen == 0)
			{
				if (mlen != null)
				{
					mlen = 0;
				}

				return true;
			}

			offset = 0;
			npub = 0;
			for (i = 0; i < rings; i++)
			{
				ulong idx = (value >> (int) (i << 1)) & 3;
				for (j = 0; j < rsizes[i]; j++)
				{
					if (npub == skip1 || npub == skip2)
					{
						npub++;
						continue;
					}

					if (idx == j)
					{
						stmp = secp256k1_rangeproof_recover_k(sec[i], ev[npub], s[npub]);
					}
					else
					{
						stmp = s[npub];
					}

					tmp = stmp.ToBytes();
					secp256k1_rangeproof_ch32xor(tmp, SafeSubarray(prep, npub * 32));
					for (b = 0; b < 32 && offset < mlen; b++)
					{
						m[offset] = tmp[b];
						offset++;
					}

					npub++;
				}
			}

			mlen = (int) offset;

			return true;
		}

		public static bool secp256k1_rangeproof_getheader_impl(ref int offset, out int exp, out int mantissa,
			out ulong scale,
			out ulong min_value, out ulong max_value, byte[] proof, int plen)
		{
			exp = -1;
			mantissa = 0;
			max_value = 0;
			min_value = 0;
			scale = 1;

			if (plen < 65 || (proof[offset] & 128) != 0)
				return false;

			bool has_nz_range = (proof[offset] & 64) != 0;
			bool has_min = (proof[offset] & 32) != 0;

			if (has_nz_range)
			{
				exp = proof[offset] & 31;
				offset += 1;
				if (exp > 18)
					return false;

				mantissa = proof[offset] + 1;
				if (mantissa > 64)
					return false;

				max_value = ulong.MaxValue >> (64 - mantissa);
			}

			offset += 1;

			for (int i = 0; i < exp; i++)
			{
				if (max_value > ulong.MaxValue / 10)
					return false;

				max_value *= 10;
				scale *= 10;
			}

			if (has_min)
			{
				if (plen - offset < 8)
					return false;

				for (int i = 0; i < 8; i++)
				{
					min_value = (min_value << 8) | proof[offset + i];
				}

				offset += 8;
			}

			if (max_value > ulong.MaxValue - min_value)
				return false;

			max_value += min_value;

			return true;
		}

		public static bool secp256k1_rangeproof_verify_impl(
			byte[] blindout, out ulong value_out, byte[] message_out, ref int outlen, byte[] nonce,
			ulong min_value, ulong max_value, GE commit, byte[] proof, int plen,
			byte[] extra_commit, int extra_commit_len, GE genp)
		{
			value_out = 0;
			GEJ accj = default;
			GEJ[] pubs = new GEJ[128];
			GE c = default;
			Scalar[] s = new Scalar[128];
			Scalar[] evalues = new Scalar[128]; // Challenges, only used during proof rewind.
			using var sha256_m = new SHA256();
			int[] rsizes = new int[32];
			bool ret;
			int i;
			int exp;
			int mantissa;
			int offset;
			int rings;
			int npub;
			uint offset_post_header;
			ulong scale;
			byte[] signs = new byte[31];
			byte[] m = new byte[33];
			byte[] e0;
			offset = 0;

			if (!secp256k1_rangeproof_getheader_impl(ref offset, out exp, out mantissa, out scale,
				    out min_value, out max_value, proof, plen))
			{
				return false;
			}

			offset_post_header = (uint) offset;
			rings = 1;
			rsizes[0] = 1;
			npub = 1;

			if (mantissa != 0)
			{
				rings = mantissa >> 1;
				for (i = 0; i < rings; i++)
				{
					rsizes[i] = 4;
				}

				npub = ((mantissa >> 1) << 2);

				if ((mantissa & 1) != 0)
				{
					rsizes[rings] = 2;
					npub += rsizes[rings];
					rings++;
				}
			}

			if (rings > 32)
				throw new InvalidOperationException("Number of rings exceeds limit.");

			if (plen - offset < (long) (32 * (npub + rings - 1) + 32 + ((rings + 6) >> 3)))
				return false;

			m = secp256k1_rangeproof_serialize_point(commit);
			sha256_m.Write(m);
			m = secp256k1_rangeproof_serialize_point(genp);
			sha256_m.Write(m);
			sha256_m.Write(SafeSubarray(proof, offset));

			for (i = 0; i < (int) (rings - 1); i++)
			{
				signs[i] = (byte) (((proof[offset + (i >> 3)] & (1 << (i & 7))) != 0) ? 1 : 0);
			}

			offset += (rings + 6) >> 3;

			if (((rings - 1) & 7) != 0)
			{
				// Number of coded blinded points is not a multiple of 8, force extra sign bits to 0 to reject mutation.
				if ((proof[offset - 1] >> (int) ((rings - 1) & 7)) != 0)
				{
					return false;
				}
			}

			npub = 0;
			accj = GEJ.Infinity;

			if (min_value != 0)
			{
				accj = Pederson.secp256k1_pedersen_ecmult_small(min_value, genp);
			}

			for (i = 0; i < (int) (rings - 1); i++)
			{
				c = new GE(new FE(SafeSubarray(proof, offset)).Sqr(), c.y);


				if (signs[i] != 0)
				{
					c = c.Negate();
				}

				sha256_m.Write(SafeSubarray(signs, 1));
				sha256_m.Write(SafeSubarray(proof, (offset + 32)));
				pubs[npub] = c.ToGroupElementJacobian();
				accj = accj.Add(c);
				offset += 32;
				npub += rsizes[i];
			}

			accj = accj.Negate();
			pubs[npub] = accj.Add(commit);

			if (pubs[npub].IsInfinity)
				return false;

			secp256k1_rangeproof_pub_expand(pubs, exp, rsizes, rings, genp);
			npub += rsizes[rings - 1];
			e0 = SafeSubarray(proof, (uint) offset, 32);
			offset += 32;

			for (i = 0; i < npub; i++)
			{
				s[i] = new Scalar(SafeSubarray(proof, offset));
				if (s[i].CheckOverflow() != 0)
					return false;

				offset += 32;
			}

			if (offset != plen)
			{
				// Extra data found, reject.
				return false;
			}

			if (extra_commit != null)
			{
				sha256_m.Write(extra_commit);
			}

			var mHash = sha256_m.GetHash();

			ret = Borromean.Verify(nonce != null ? evalues : null, e0, s, pubs, rsizes, rings, mHash);

			if (ret && nonce != null)
			{
				// Given the nonce, try rewinding the witness to recover its initial state.
				Scalar blind = default;
				ulong vv = 0;

				if (!secp256k1_rangeproof_rewind_inner(out blind, ref vv, message_out, ref outlen, evalues, s,
					    rsizes, rings, nonce, commit, proof, offset_post_header, genp))
				{
					return false;
				}

				// Unwind apparently successful, see if the commitment can be reconstructed.
				vv = (vv * scale) + min_value;
				accj = Pederson.secp256k1_pedersen_ecmult(blind, vv, genp);

				if (accj.IsInfinity)
					return false;

				accj = accj.Negate();
				accj.Add(commit);
				if (accj.IsInfinity)
					return false;

				if (blindout != null)
				{
					blindout = blind.ToBytes();
				}

				value_out = vv;
			}
			else
			{
				value_out = 0;
			}

			return ret;
		}
	}
}
#endif

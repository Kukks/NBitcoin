using NBitcoin.Secp256k1;

public static class Secp256k1RangeProof
{


	public static bool GetProofInfo(out int exp, out int mantissa, out ulong minValue, out ulong maxValue, byte[] proof)
	{
		int offset = 0;
		ulong scale = 1;

		return Rangeproof.secp256k1_rangeproof_getheader_impl(ref offset, out exp, out mantissa, out scale,
			out minValue, out maxValue, proof, proof.Length);

	}

	public static int RewindProof(out byte[] blindOut, out ulong valueOut, out byte[] messageOut, ref int outLen,
		byte[] nonce, ref ulong minValue, ref ulong maxValue, byte[] commit, byte[] proof,
		byte[] extraCommit, int extraCommitLen)
	{
		GE commitP = new GE();
		GE genP = new GE();

		secp256k1_pedersen_commitment_load(ref commitP, commit);
		secp256k1_generator_load(ref genP, Context.Instance.GF);

		var result = Rangeproof.secp256k1_rangeproof_verify_impl(null, null, out valueOut,
			outLen > 0 ? new byte[outLen] : null, ref outLen, null, ref minValue, ref maxValue, ref commitP, proof,
			proof.Length, extraCommit, extraCommitLen, ref genP);

		if (result)
		{
			blindOut = new byte[32];
			messageOut = new byte[outLen];
			result = Rangeproof.secp256k1_rangeproof_rewind_inner(blindOut, out valueOut, messageOut, ref outLen, nonce,
				ref minValue, ref maxValue, ref commitP, proof, proof.Length, extraCommit, extraCommitLen, ref genP);
		}
		else
		{
			blindOut = null;
			messageOut = null;
			valueOut = 0;
		}

		return result;
	}

	public static int VerifyProof(ref ulong minValue, ref ulong maxValue, byte[] commit,
		byte[] proof, byte[] extraCommit, int extraCommitLen, GEnerator gen)
	{
		GE commitP = new GE();
		GE genP = new GE();

		secp256k1_pedersen_commitment_load(ref commitP, commit);
		secp256k1_generator_load(ref genP, gen);

		return secp256k1_rangeproof_verify_impl(null, null, null, null, null, null, ref minValue, ref maxValue,
			ref commitP, proof, proof.Length, extraCommit, extraCommitLen, ref genP);
	}

	public static int SignProof(out byte[] proof, ref int proofLen, ulong minValue, byte[] commit,
		byte[] blind, byte[] nonce, int exp, int minBits, ulong value, byte[] message, int msgLen, byte[] extraCommit,
		int extraCommitLen, GEnerator gen)
	{
		GE commitP = new GE();
		GE genP = new GE();

		secp256k1_pedersen_commitment_load(ref commitP, commit);
		secp256k1_generator_load(ref genP, gen);

		proof = new byte[proofLen];
		int result = secp256k1_rangeproof_sign_impl(proof, ref proofLen, minValue, ref commitP, blind, nonce, exp,
			minBits, value, message, msgLen, extraCommit, extraCommitLen, ref genP);

		return result;
	}

	public static int GetMaxProofSize(ulong maxValue, int minBits)
	{
		int valMantissa = (maxValue > 0) ? 64 - Rangeproof.secp256k1_clz64_var(maxValue) : 1;
		int mantissa = (minBits > valMantissa) ? minBits : valMantissa;
		int rings = (mantissa + 1) / 2;
		int npubs = rings * 4 - 2 * (mantissa % 2);

		return 10 + 32 * (npubs + rings - 1) + 32 + ((rings - 1 + 7) / 8);
	}
}

using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace MHCCrypto {
	/// <summary>
	/// Base metahash cryptography
	/// </summary>
	public static class Crypto {
		/// <summary>
		/// Create random EC private key based on secp256r1
		/// </summary>
		public static string CreatePrivateKey() {
			// creating private key
			SecureRandom secureRandom = new SecureRandom();
			X9ECParameters ecParams = SecNamedCurves.GetByName("secp256r1");
			ECDomainParameters ccdParams = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());
			ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(ccdParams, secureRandom);
			ECKeyPairGenerator generator = new ECKeyPairGenerator("ECDH");
			generator.Init(keyGenParams);

			// getting public key
			AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
			ECPrivateKeyParameters privParams = keyPair.Private as ECPrivateKeyParameters;
			PrivateKeyInfo privInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privParams);
			ECPoint q = privParams.Parameters.G.Multiply(privParams.D);
			ECPublicKeyParameters pubParams = new ECPublicKeyParameters(privParams.AlgorithmName, q, privParams.Parameters);
			SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubParams);

			// ugly hack
			byte[] der = privInfo.GetDerEncoded();
			byte[] privateKey = der.Skip(der.Length - 32).ToArray();
			der = pubInfo.GetDerEncoded();
			byte[] publicKey = der.Skip(der.Length - 65).ToArray();

			// repack DER
			DerSequence seq = new DerSequence(
				new DerInteger(1),
				new DerOctetString(privateKey),
				new DerTaggedObject(0, new DerObjectIdentifier("1.2.840.10045.3.1.7")),
				new DerTaggedObject(1, new DerBitString(publicKey))
			);

			der = seq.GetDerEncoded();
			return Hex.ToHexString(der);
		}

		/// <summary>
		/// Get public key from private
		/// </summary>
		public static string GetPublicKey(string privateKey) {
			try {
				Asn1Object privKeyObj = Asn1Object.FromByteArray(Hex.Decode(privateKey));
				ECPrivateKeyStructure privStruct = ECPrivateKeyStructure.GetInstance(privKeyObj);
				AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, privStruct.GetParameters());
				PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, privKeyObj);
				ECPrivateKeyParameters keyParams = PrivateKeyFactory.CreateKey(privInfo) as ECPrivateKeyParameters;
				ECPoint q = keyParams.Parameters.G.Multiply(keyParams.D);
				var publicParams = new ECPublicKeyParameters(keyParams.AlgorithmName, q, keyParams.PublicKeyParamSet);
				byte[] der = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicParams).GetDerEncoded();
				return Hex.ToHexString(der);
			} catch {
				return null;
			}
		}

		/// <summary>
		/// Parse public key to raw data
		/// </summary>
		public static byte[] ParsePrivateKey(string privateKey) {
			try {
				var parser = new Asn1StreamParser(Hex.Decode(privateKey));
				var sequence = parser.ReadObject() as DerSequenceParser;
				if (sequence != null) {
					var o1 = sequence.ReadObject() as DerInteger;
					var o2 = sequence.ReadObject() as DerOctetStringParser;
					byte[] octets = new byte[32];
					using (MemoryStream ms = new MemoryStream()) {
						o2.GetOctetStream().CopyTo(ms);
						var o3 = sequence.ReadObject() as BerTaggedObjectParser;
						var o4 = o3.GetObjectParser(0, true) as DerObjectIdentifier;
						if (o4.Id == "1.2.840.10045.3.1.7" && o1.Value.Equals(new BigInteger("1"))) {
							return ms.ToArray();
						}
					}
				}
				return null;
			} catch {
				return null;
			}
		}

		/// <summary>
		/// Parse private key to raw data
		/// </summary>
		public static byte[] ParsePublicKey(string publicKey) {
			try {
				var parser = new Asn1StreamParser(Hex.Decode(publicKey));
				Asn1SequenceParser sequence = parser.ReadObject() as Asn1SequenceParser;
				if (sequence != null) {
					var o1 = sequence.ReadObject();
					var oid = sequence.ReadObject() as DerObjectIdentifier;
					if (oid.Id == "1.2.840.10045.2.1") {
						oid = sequence.ReadObject() as DerObjectIdentifier;
						if (oid.Id == "1.2.840.10045.3.1.7" || oid.Id == "1.3.132.0.10") {
							var bits = sequence.ReadObject() as DerBitString;
							return bits.GetBytes();
						}
					}
					return null;
				} else {
					return null;
				}
			} catch {
				return null;
			}
		}

		/// <summary>
		/// Encode raw public key assume secp256r1
		/// </summary>
		public static string EncodePublicKey(byte[] publicKey) {
			DerSequence pKey = new DerSequence(
				new DerSequence(
					new DerObjectIdentifier("1.2.840.10045.2.1"),
					new DerObjectIdentifier("1.2.840.10045.3.1.7")
				),
				new DerBitString(publicKey)
			);
			return Hex.ToHexString(pKey.GetDerEncoded());
		}

		/// <summary>
		/// Encode private key assume secp256r1
		/// </summary>
		public static string EncodePrviateKey(byte[] publicKey, byte[] privateKey) {
			// repack DER
			DerSequence seq = new DerSequence(
				new DerInteger(1),
				new DerOctetString(privateKey),
				new DerTaggedObject(0, new DerObjectIdentifier("1.2.840.10045.3.1.7")),
				new DerTaggedObject(1, new DerBitString(publicKey))
			);

			byte[] der = seq.GetDerEncoded();
			return Hex.ToHexString(der);
		}

		/// <summary>
		/// Encode private key from 32 byte representation assume secp256r1
		/// </summary>
		/// <param name="privateKey"></param>
		/// <returns></returns>
		public static string EncodePrivateKey(byte[] privateKey) {
			var curve = SecNamedCurves.GetByName("secp256r1");
			var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
			BigInteger d = new BigInteger(privateKey);
			ECPoint q = domain.G.Multiply(d);
			var publicParams = new ECPublicKeyParameters(q, domain);
			return EncodePrviateKey(publicParams.Q.GetEncoded(), privateKey);
		}

		/// <summary>
		/// Ripemd160 hash 
		/// </summary>
		static public byte[] RipeMD160Hash(byte[] data) {
			RipeMD160Digest digest = new RipeMD160Digest();
			digest.BlockUpdate(data, 0, data.Length);
			byte[] hash = new byte[digest.GetDigestSize()];
			digest.DoFinal(hash, 0);
			return hash;
		}

		/// <summary>
		/// HMAC-SHA256 hash
		/// </summary>
		public static byte[] HmacSha256(byte[] data, byte[] key) {
			var hmac = new HMac(new Sha256Digest());
			hmac.Init(new KeyParameter(key));
			byte[] hash = new byte[hmac.GetMacSize()];
			hmac.BlockUpdate(data, 0, data.Length);
			hmac.DoFinal(hash, 0);
			return hash;
		}

		/// <summary>
		/// Sha256 hash
		/// </summary>
		static public byte[] Sha256Hash(byte[] data) {
			Sha256Digest digest = new Sha256Digest();
			digest.BlockUpdate(data, 0, data.Length);
			byte[] hash = new byte[digest.GetDigestSize()];
			digest.DoFinal(hash, 0);
			return hash;
		}

		/// <summary>
		/// Get address from public key
		/// </summary>
		public static string GetAddress(string publicKey) {
			byte[] bytes = bytes = RipeMD160Hash(Sha256Hash(ParsePublicKey(publicKey)));
			byte[] ripemd = new byte[] { 0x00 }.Concat(bytes).ToArray();
			bytes = ripemd.Concat(Sha256Hash(Sha256Hash(ripemd)).Take(4)).ToArray();
			return "0x" + Hex.ToHexString(bytes);
		}

		/// <summary>
		/// Sign specified data
		/// </summary>
		public static string Sign(byte[] data, string privateKey) {
			Asn1Object privKeyObj = Asn1Object.FromByteArray(Hex.Decode(privateKey));
			ECPrivateKeyStructure privStruct = ECPrivateKeyStructure.GetInstance(privKeyObj);
			AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, privStruct.GetParameters());
			PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, privKeyObj);
			ECPrivateKeyParameters par = PrivateKeyFactory.CreateKey(privInfo) as ECPrivateKeyParameters;
			ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
			signer.Init(true, par);
			signer.BlockUpdate(data, 0, data.Length);
			return Hex.ToHexString(signer.GenerateSignature());
		}

		/// <summary>
		/// Check sign for specified data
		/// </summary>
		public static bool Verify(byte[] data, string sign, string publicKey) {
			ECPublicKeyParameters par = PublicKeyFactory.CreateKey(Hex.Decode(publicKey)) as ECPublicKeyParameters;
			ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
			signer.Init(false, par);
			signer.BlockUpdate(data, 0, data.Length);
			return signer.VerifySignature(Hex.Decode(sign));
		}
	}
}

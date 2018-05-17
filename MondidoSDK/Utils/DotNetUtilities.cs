using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Mondido.Utils
{
    public class DotNetUtilities
    {
        public static RSA ToRSA(RsaKeyParameters rsaKey)
        {
            // TODO This appears to not work for private keys (when no CRT info)
            return CreateRSAProvider(ToRSAParameters(rsaKey));
        }

        public static RSA ToRSA(RsaKeyParameters rsaKey, CspParameters csp)
        {
            // TODO This appears to not work for private keys (when no CRT info)
            return CreateRSAProvider(ToRSAParameters(rsaKey), csp);
        }

        public static RSA ToRSA(RsaPrivateCrtKeyParameters privKey)
        {
            return CreateRSAProvider(ToRSAParameters(privKey));
        }

        public static RSA ToRSA(RsaPrivateCrtKeyParameters privKey, CspParameters csp)
        {
            return CreateRSAProvider(ToRSAParameters(privKey), csp);
        }

        public static RSA ToRSA(RsaPrivateKeyStructure privKey)
        {
            return CreateRSAProvider(ToRSAParameters(privKey));
        }

        public static RSA ToRSA(RsaPrivateKeyStructure privKey, CspParameters csp)
        {
            return CreateRSAProvider(ToRSAParameters(privKey), csp);
        }

        public static RSAParameters ToRSAParameters(RsaKeyParameters rsaKey)
        {
            RSAParameters rp = new RSAParameters();
            rp.Modulus = rsaKey.Modulus.ToByteArrayUnsigned();
            if (rsaKey.IsPrivate)
                rp.D = ConvertRSAParametersField(rsaKey.Exponent, rp.Modulus.Length);
            else
                rp.Exponent = rsaKey.Exponent.ToByteArrayUnsigned();
            return rp;
        }

        public static RSAParameters ToRSAParameters(RsaPrivateCrtKeyParameters privKey)
        {
            RSAParameters rp = new RSAParameters();
            rp.Modulus = privKey.Modulus.ToByteArrayUnsigned();
            rp.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
            rp.P = privKey.P.ToByteArrayUnsigned();
            rp.Q = privKey.Q.ToByteArrayUnsigned();
            rp.D = ConvertRSAParametersField(privKey.Exponent, rp.Modulus.Length);
            rp.DP = ConvertRSAParametersField(privKey.DP, rp.P.Length);
            rp.DQ = ConvertRSAParametersField(privKey.DQ, rp.Q.Length);
            rp.InverseQ = ConvertRSAParametersField(privKey.QInv, rp.Q.Length);
            return rp;
        }

        public static RSAParameters ToRSAParameters(RsaPrivateKeyStructure privKey)
        {
            RSAParameters rp = new RSAParameters();
            rp.Modulus = privKey.Modulus.ToByteArrayUnsigned();
            rp.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
            rp.P = privKey.Prime1.ToByteArrayUnsigned();
            rp.Q = privKey.Prime2.ToByteArrayUnsigned();
            rp.D = ConvertRSAParametersField(privKey.PrivateExponent, rp.Modulus.Length);
            rp.DP = ConvertRSAParametersField(privKey.Exponent1, rp.P.Length);
            rp.DQ = ConvertRSAParametersField(privKey.Exponent2, rp.Q.Length);
            rp.InverseQ = ConvertRSAParametersField(privKey.Coefficient, rp.Q.Length);
            return rp;
        }

        // TODO Move functionality to more general class
        private static byte[] ConvertRSAParametersField(BigInteger n, int size)
        {
            byte[] bs = n.ToByteArrayUnsigned();

            if (bs.Length == size)
                return bs;

            if (bs.Length > size)
                throw new ArgumentException("Specified size too small", "size");

            byte[] padded = new byte[size];
            Array.Copy(bs, 0, padded, size - bs.Length, bs.Length);
            return padded;
        }

        private static RSA CreateRSAProvider(RSAParameters rp)
        {
            CspParameters csp = new CspParameters();
            csp.KeyContainerName = string.Format("BouncyCastle-{0}", Guid.NewGuid());
            RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider(csp);
            rsaCsp.ImportParameters(rp);
            return rsaCsp;
        }

        private static RSA CreateRSAProvider(RSAParameters rp, CspParameters csp)
        {
            RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider(csp);
            rsaCsp.ImportParameters(rp);
            return rsaCsp;
        }
    }
}

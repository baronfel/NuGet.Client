// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace Test.Utility.Signing
{
    internal class BcVerifier
    {
        internal void Verify(
            byte[] requestBytes,
            byte[] responseBytes,
            byte[] caCertificateBytes,
            OcspRequest ocspRequest,
            OcspResponse ocspResponse,
            List<System.Security.Cryptography.X509Certificates.X509Certificate2> certificateChain,
            Test.Utility.Signing.CertStatus certStatus,
            System.Security.Cryptography.RSA keyPair)
        {
            List<X509Certificate> bcCertificateChain = GetCertificateChain(certificateChain);
            X509Certificate caCertificate = ReadCertificate(caCertificateBytes);
            OcspReq ocspReq = new(requestBytes);

            byte[] bcReqEncoded = ocspReq.GetEncoded();
            string bcReqBase64Encoded = Convert.ToBase64String(bcReqEncoded);

            var respId = new RespID(caCertificate.SubjectDN);
            var basicOcspRespGenerator = new BasicOcspRespGenerator(respId);
            var requests = ocspReq.GetRequestList();
            var nonce = ocspReq.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce);

            if (nonce != null)
            {
                var extensions = new X509Extensions(new Dictionary<DerObjectIdentifier, X509Extension>()
                {
                    { OcspObjectIdentifiers.PkixOcspNonce, new X509Extension(critical: false, value: nonce) }
                });

                basicOcspRespGenerator.SetResponseExtensions(extensions);
            }

            var now = DateTimeOffset.UtcNow;

            foreach (var request in requests)
            {
                var certificateId = request.GetCertID();
                Org.BouncyCastle.Ocsp.CertificateStatus certificateStatus = certStatus.TagNo == 0 ? Org.BouncyCastle.Ocsp.CertificateStatus.Good : new Org.BouncyCastle.Ocsp.RevokedStatus(DateTime.UtcNow, 3);
                var thisUpdate = now;
                //On Windows, if the current time is equal (to the second) to a notAfter time (or nextUpdate time), it's considered valid.
                //But OpenSSL considers it already expired (that the expiry happened when the clock changed to this second)
                var nextUpdate = now.AddSeconds(2);

                basicOcspRespGenerator.AddResponse(certificateId, certificateStatus, thisUpdate.UtcDateTime, nextUpdate.UtcDateTime, singleExtensions: null);
            }
            var bcKeyPair = ConvertToBouncyCastleKeyPair(keyPair);
            var basicOcspResp = basicOcspRespGenerator.Generate("SHA256WITHRSA", bcKeyPair.Private, bcCertificateChain.ToArray(), now.UtcDateTime);
            var ocspRespGenerator = new OCSPRespGenerator();
            var ocspResp = ocspRespGenerator.Generate(OCSPRespGenerator.Successful, basicOcspResp);

            var respEncoded = ocspResp.GetEncoded();
            var respBase64Encoded = Convert.ToBase64String(respEncoded);

            AsnWriter writer = new(AsnEncodingRules.DER);

            ocspResponse.Encode(writer);

            var ocspResponseEncoded = writer.Encode();
            var ocspResponseBase64Encoded = Convert.ToBase64String(ocspResponseEncoded);

            var bcResp = respBase64Encoded;
            var myResp = ocspResponseBase64Encoded;
        }

        private List<X509Certificate> GetCertificateChain(List<System.Security.Cryptography.X509Certificates.X509Certificate2> certificateChain)
        {
            return certificateChain
                .Select(c => ReadCertificate(c.RawData))
                .ToList();
        }

        public static AsymmetricCipherKeyPair ConvertToBouncyCastleKeyPair(RSA rsa)
        {
            RSAParameters rsaParams = rsa.ExportParameters(true);

            // Create BouncyCastle RSA parameters
            RsaKeyParameters publicKeyParams = new RsaKeyParameters(false, new BigInteger(1, rsaParams.Modulus), new BigInteger(1, rsaParams.Exponent));
            RsaPrivateCrtKeyParameters privateKeyParams = new RsaPrivateCrtKeyParameters(
                new BigInteger(1, rsaParams.Modulus),
                new BigInteger(1, rsaParams.Exponent),
                new BigInteger(1, rsaParams.D),
                new BigInteger(1, rsaParams.P),
                new BigInteger(1, rsaParams.Q),
                new BigInteger(1, rsaParams.DP),
                new BigInteger(1, rsaParams.DQ),
                new BigInteger(1, rsaParams.InverseQ)
            );

            // Create AsymmetricCipherKeyPair
            AsymmetricCipherKeyPair keyPair = new AsymmetricCipherKeyPair(publicKeyParams, privateKeyParams);
            return keyPair;
        }

        private static X509Certificate ReadCertificate(byte[] bytes)
        {
            X509CertificateParser certificateParser = new();

            return certificateParser.ReadCertificate(bytes);
        }
    }
}

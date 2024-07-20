// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#nullable enable

using System;
#if IS_SIGNING_SUPPORTED
using System.Collections.Generic;
using System.Formats.Asn1;
#endif
using System.IO;
using System.Numerics;
#if IS_SIGNING_SUPPORTED
using System.Security.Cryptography;
#endif
using System.Security.Cryptography.X509Certificates;

namespace Test.Utility.Signing
{
    public class CertificateRevocationList : IDisposable
    {
        public Crl Crl { get; set; }

        public X509CertificateWithKeyInfo IssuerCert { get; private set; }

        public string CrlLocalPath { get; private set; }

        public BigInteger Version { get; private set; }

        private CertificateRevocationList(
            Crl crl,
            X509CertificateWithKeyInfo issuerCert,
            string crlLocalPath,
            BigInteger version)
        {
            Crl = crl;
            IssuerCert = issuerCert;
            CrlLocalPath = crlLocalPath;
            Version = version;
        }

#if IS_SIGNING_SUPPORTED
        public static CertificateRevocationList CreateCrl(
            X509CertificateWithKeyInfo issuerCert,
            string crlLocalUri)
        {
            var version = BigInteger.One;
            var crl = CreateCrl(issuerCert, version);

            return new CertificateRevocationList(
                crl,
                issuerCert,
                Path.Combine(crlLocalUri, $"{issuerCert.Certificate.Subject}.crl"),
                version);
        }

        private static Crl CreateCrl(
            X509CertificateWithKeyInfo issuerCert,
            BigInteger version,
            X509Certificate2? revokedCertificate = null)
        {
            byte[] versionBigEndian = version.ToByteArray();
            Array.Reverse(versionBigEndian);

            AlgorithmIdentifier signatureAlgorithm = new(issuerCert.Certificate.SignatureAlgorithm);
            List<RevokedCertificate> revokedCertificates = new();

            if (revokedCertificate is not null)
            {
                BigInteger privilegeWithdrawn = new(9);

                X509ExtensionAsn crlReasonExtension = new()
                {
                    ExtnId = TestOids.CrlReasons.Value!,
                    ExtnValue = privilegeWithdrawn.ToByteArray(),
                    Critical = false
                };

                revokedCertificates.Add(
                    new RevokedCertificate(
                        new BigInteger(revokedCertificate.GetSerialNumber()),
                        DateTimeOffset.Now,
                        crlEntryExtensions: [crlReasonExtension]));
            }

            List<X509ExtensionAsn> certificateExtensions = new();

            X509AuthorityKeyIdentifierExtension extension = X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
                issuerCert.Certificate,
                includeKeyIdentifier: true,
                includeIssuerAndSerial: true);

            AsnReader reader = new(extension.RawData, AsnEncodingRules.DER);
            X509ExtensionAsn.Decode(ref reader, rebind: default, out X509ExtensionAsn decoded);

            reader = new AsnReader(issuerCert.Certificate.SubjectName.RawData, AsnEncodingRules.DER);
            GeneralName issuerName = GeneralName.Decode(reader);

            certificateExtensions.Add(decoded);
            certificateExtensions.Add(
                new X509ExtensionAsn()
                {
                    ExtnId = TestOids.CrlNumber.Value!,
                    ExtnValue = versionBigEndian,
                    Critical = false
                });

            TbsCertList tbsCertList = new TbsCertList(
                version,
                signatureAlgorithm,
                issuerName,
                DateTimeOffset.Now,
                DateTimeOffset.Now.AddYears(1),
                revokedCertificates,
                certificateExtensions);

            AsnWriter writer = new(AsnEncodingRules.DER);

            byte[] encoded = writer.Encode();
            byte[] hash;

            using (HashAlgorithm hashAlgorithm = SHA256.Create())
            {
                hash = hashAlgorithm.ComputeHash(encoded);
            }

            var rsaFormatter = new RSAPKCS1SignatureFormatter(issuerCert.KeyPair);

            rsaFormatter.SetHashAlgorithm(HashAlgorithmName.SHA256.Name!);

            byte[] signature = rsaFormatter.CreateSignature(hash);

            return new Crl(tbsCertList, signatureAlgorithm, signature);
        }

        public void RevokeCertificate(X509Certificate2 revokedCertificate)
        {
            UpdateVersion();
            Crl = CreateCrl(IssuerCert, Version, revokedCertificate);
            ExportCrl();
        }

        public void ExportCrl()
        {
            byte[] encoded = Crl.Encode();
            string base64 = Convert.ToBase64String(encoded);

            using (StreamWriter streamWriter = new(File.Open(CrlLocalPath, FileMode.Create)))
            {
                const string label = "X509 CRL";
                streamWriter.WriteLine($"-----BEGIN {label}-----");
                streamWriter.WriteLine(base64);
                streamWriter.WriteLine($"-----END {label}-----");
            }
        }

        private void UpdateVersion()
        {
            Version += BigInteger.One;
        }
#else
        public static CertificateRevocationList CreateCrl(X509CertificateWithKeyInfo certCA, string crlLocalUri)
        {
            throw new NotImplementedException();
        }

        public void RevokeCertificate(X509Certificate2 revokedCertificate)
        {
            throw new NotImplementedException();
        }

        public void ExportCrl()
        {
            throw new NotImplementedException();
        }
#endif

        public void Dispose()
        {
            if (!string.IsNullOrEmpty(CrlLocalPath) && File.Exists(CrlLocalPath))
            {
                File.Delete(CrlLocalPath);
            }
        }
    }
}

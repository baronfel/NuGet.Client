// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;

namespace Test.Utility.Signing
{
    /*
        From RFC 5280 (https://www.rfc-editor.org/rfc/rfc5280#section-5.1):

           TBSCertList  ::=  SEQUENCE  {
                version                 Version OPTIONAL,
                                             -- if present, MUST be v2
                signature               AlgorithmIdentifier,
                issuer                  Name,
                thisUpdate              Time,
                nextUpdate              Time OPTIONAL,
                revokedCertificates     SEQUENCE OF SEQUENCE  {
                     userCertificate         CertificateSerialNumber,
                     revocationDate          Time,
                     crlEntryExtensions      Extensions OPTIONAL
                                              -- if present, version MUST be v2
                                          }  OPTIONAL,
                crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                              -- if present, version MUST be v2
                                          }

            Name ::= CHOICE { -- only one possibility for now --
              rdnSequence  RDNSequence }

            RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

            DistinguishedName ::=   RDNSequence

            RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue

            AttributeTypeAndValue ::= SEQUENCE {
              type     AttributeType,
              value    AttributeValue }

            AttributeType ::= OBJECT IDENTIFIER
            AttributeValue ::= ANY -- DEFINED BY AttributeType
    */
    internal sealed class TbsCertList
    {
        internal BigInteger Version { get; }
        internal AlgorithmIdentifier SignatureAlgorithm { get; }
        internal GeneralName Issuer { get; }
        internal DateTimeOffset ThisUpdate { get; }
        internal DateTimeOffset? NextUpdate { get; }
        internal IReadOnlyList<RevokedCertificate> RevokedCertificates { get; }
        internal IReadOnlyList<X509ExtensionAsn> CrlExtensions { get; }

        internal TbsCertList(
            BigInteger version,
            AlgorithmIdentifier signatureAlgorithm,
            GeneralName issuer,
            DateTimeOffset thisUpdate,
            DateTimeOffset? nextUpdate,
            IReadOnlyList<RevokedCertificate> revokedCertificates,
            IReadOnlyList<X509ExtensionAsn> crlExtensions)
        {
            Version = version;
            SignatureAlgorithm = signatureAlgorithm;
            Issuer = issuer;
            ThisUpdate = thisUpdate;
            NextUpdate = nextUpdate;
            RevokedCertificates = revokedCertificates;
            CrlExtensions = crlExtensions;
        }

        internal static TbsCertList Decode(AsnReader reader)
        {
            if (reader is null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            AsnReader sequenceReader = reader.ReadSequence();

            BigInteger version;

            if (sequenceReader.PeekTag() == Asn1Tag.Integer)
            {
                version = sequenceReader.ReadInteger();
            }
            else
            {
                version = 2;
            }

            AlgorithmIdentifier signatureAlgorithm = AlgorithmIdentifier.Decode(sequenceReader);
            GeneralName issuer = GeneralName.Decode(sequenceReader);
            DateTimeOffset? thisUpdate = sequenceReader.ReadTime();
            DateTimeOffset? nextUpdate = sequenceReader.ReadTime();

            if (thisUpdate is null)
            {
                throw new CryptographicException("Invalid ASN.1");
            }

            List<RevokedCertificate> revokedCertificates = new();
            Asn1Tag context0 = new(TagClass.ContextSpecific, 0);

            if (sequenceReader.HasData)
            {
                if (!sequenceReader.PeekTag().HasSameClassAndValue(context0))
                {
                    AsnReader revokedCertificatesReader = sequenceReader.ReadSequence();

                    while (revokedCertificatesReader.HasData)
                    {
                        RevokedCertificate revokedCertificate = RevokedCertificate.Decode(revokedCertificatesReader);

                        revokedCertificates.Add(revokedCertificate);
                    }
                }
            }

            List<X509ExtensionAsn> crlExtensions = new();

            if (sequenceReader.HasData)
            {
                if (!sequenceReader.PeekTag().HasSameClassAndValue(context0))
                {
                    throw new CryptographicException("Invalid ASN.1");
                }

                while (sequenceReader.HasData)
                {
                    X509ExtensionAsn.Decode(ref sequenceReader, rebind: default, out X509ExtensionAsn extension);

                    crlExtensions.Add(extension);
                }
            }

            return new TbsCertList(
                version,
                signatureAlgorithm,
                issuer,
                thisUpdate.Value,
                nextUpdate,
                revokedCertificates,
                crlExtensions);
        }

        internal void Encode(AsnWriter writer)
        {
            if (writer is null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            writer.WriteInteger(Version);
            SignatureAlgorithm.Encode(writer);
            Issuer.Encode(writer);
            writer.WriteUtcTime(ThisUpdate);

            if (NextUpdate is not null)
            {
                writer.WriteUtcTime(NextUpdate.Value);
            }

            if (RevokedCertificates.Count > 0)
            {
                using (writer.PushSequence())
                {
                    foreach (RevokedCertificate revokedCertificate in RevokedCertificates)
                    {
                        revokedCertificate.Encode(writer);
                    }
                }
            }

            if (CrlExtensions.Count > 0)
            {
                using (writer.PushSequence())
                {
                    foreach (X509ExtensionAsn extension in CrlExtensions)
                    {
                        extension.Encode(writer);
                    }
                }
            }
        }
    }
}

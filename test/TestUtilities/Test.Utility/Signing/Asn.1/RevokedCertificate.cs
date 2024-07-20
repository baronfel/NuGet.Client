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

                revokedCertificate       SEQUENCE  {
                     userCertificate         CertificateSerialNumber,
                     revocationDate          Time,
                     crlEntryExtensions      Extensions OPTIONAL
                                              -- if present, version MUST be v2
                                          }  OPTIONAL,
    */
    internal sealed class RevokedCertificate
    {
        internal BigInteger UserCertificate { get; }
        internal DateTimeOffset RevocationDate { get; }
        internal IReadOnlyList<X509ExtensionAsn> CrlEntryExtensions { get; }

        internal RevokedCertificate(
            BigInteger userCertificate,
            DateTimeOffset revocationDate,
            IReadOnlyList<X509ExtensionAsn> crlEntryExtensions)
        {
            UserCertificate = userCertificate;
            RevocationDate = revocationDate;
            CrlEntryExtensions = crlEntryExtensions;
        }

        internal static RevokedCertificate Decode(AsnReader reader)
        {
            if (reader is null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            AsnReader sequenceReader = reader.ReadSequence();

            BigInteger userCertificate = sequenceReader.ReadInteger();
            DateTimeOffset? revocationDate = sequenceReader.ReadTime();

            if (revocationDate is null)
            {
                throw new CryptographicException("Invalid ASN.1.");
            }

            List<X509ExtensionAsn> extensions = new();

            while (sequenceReader.HasData)
            {
                X509ExtensionAsn.Decode(ref sequenceReader, rebind: default, out X509ExtensionAsn extension);

                extensions.Add(extension);
            }

            return new RevokedCertificate(userCertificate, revocationDate.Value, extensions);
        }

        internal void Encode(AsnWriter writer)
        {
            if (writer is null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            using (writer.PushSequence())
            {
                writer.WriteInteger(UserCertificate);
                writer.WriteUtcTime(RevocationDate);

                if (CrlEntryExtensions.Count > 0)
                {
                    using (writer.PushSequence())
                    {
                        foreach (X509ExtensionAsn extension in CrlEntryExtensions)
                        {
                            extension.Encode(writer);
                        }
                    }
                }
            }
        }
    }
}

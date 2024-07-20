// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Formats.Asn1;

namespace Test.Utility.Signing
{
    /*
        From RFC 5280 (https://www.rfc-editor.org/rfc/rfc5280#section-5.1):

           CertificateList  ::=  SEQUENCE  {
            tbsCertList          TBSCertList,
            signatureAlgorithm   AlgorithmIdentifier,
            signatureValue       BIT STRING  }
    */
    public sealed class Crl
    {
        internal TbsCertList TbsCertList { get; }
        internal AlgorithmIdentifier SignatureAlgorithm { get; }
        internal ReadOnlyMemory<byte> Signature { get; }

        internal Crl(
            TbsCertList tbsCertList,
            AlgorithmIdentifier signatureAlgorithm,
            ReadOnlyMemory<byte> signature)
        {
            if (tbsCertList is null)
            {
                throw new ArgumentNullException(nameof(tbsCertList));
            }

            TbsCertList = tbsCertList;
            SignatureAlgorithm = signatureAlgorithm;
            Signature = signature;
        }

        internal static Crl Decode(AsnReader reader)
        {
            if (reader is null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            AsnReader sequenceReader = reader.ReadSequence();
            TbsCertList tbsCertList = TbsCertList.Decode(sequenceReader);
            AlgorithmIdentifier signatureAlgorithm = AlgorithmIdentifier.Decode(sequenceReader);
            ReadOnlyMemory<byte> signature = sequenceReader.ReadBitString(out _);

            return new Crl(tbsCertList, signatureAlgorithm, signature);
        }

        internal void Encode(AsnWriter writer)
        {
            if (writer is null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            using (writer.PushSequence())
            {
                TbsCertList.Encode(writer);
                SignatureAlgorithm.Encode(writer);
                writer.WriteBitString(Signature.Span);
            }
        }

        internal byte[] Encode()
        {
            AsnWriter writer = new(AsnEncodingRules.DER);

            Encode(writer);

            return writer.Encode();
        }
    }
}

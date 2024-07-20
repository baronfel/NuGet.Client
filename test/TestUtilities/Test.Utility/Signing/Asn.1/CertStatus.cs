// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#nullable enable

using System;
using System.Formats.Asn1;

namespace Test.Utility.Signing
{
    /*
        From RFC 6960 (https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1):

           CertStatus ::= CHOICE {
               good        [0]     IMPLICIT NULL,
               revoked     [1]     IMPLICIT RevokedInfo,
               unknown     [2]     IMPLICIT UnknownInfo }

           UnknownInfo ::= NULL
    */
    internal sealed class CertStatus
    {
        private readonly ReadOnlyMemory<byte> _status;

        internal int TagNo { get; }

        private CertStatus(int tagNo, ReadOnlyMemory<byte> status)
        {
            TagNo = tagNo;
            _status = status;
        }

        internal static CertStatus FromGood()
        {
            AsnWriter writer = new(AsnEncodingRules.DER);

            writer.WriteNull(Asn1Tags.ContextSpecific0);

            return new CertStatus(0, writer.Encode());
        }

        internal static CertStatus FromRevoked(RevokedInfo revokedInfo)
        {
            AsnWriter writer = new(AsnEncodingRules.DER);

            revokedInfo.Encode(writer, Asn1Tags.ContextSpecific1);

            return new CertStatus(1, writer.Encode());
        }

        internal static CertStatus FromUnknown()
        {
            AsnWriter writer = new(AsnEncodingRules.DER);

            writer.WriteNull(Asn1Tags.ContextSpecific2);

            return new CertStatus(2, writer.Encode());
        }

        internal void Encode(AsnWriter writer)
        {
            if (writer is null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            writer.WriteEncodedValue(_status.Span);
        }
    }
}

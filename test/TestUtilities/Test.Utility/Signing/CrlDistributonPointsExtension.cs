// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace Test.Utility.Signing
{
    //
    /*
        From RFC 5280 (https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.13):

            id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 }

            CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

            DistributionPoint ::= SEQUENCE {
                distributionPoint       [0]     DistributionPointName OPTIONAL,
                reasons                 [1]     ReasonFlags OPTIONAL,
                cRLIssuer               [2]     GeneralNames OPTIONAL }

            DistributionPointName ::= CHOICE {
                fullName                [0]     GeneralNames,
                nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

            ReasonFlags ::= BIT STRING {
                unused                  (0),
                keyCompromise           (1),
                cACompromise            (2),
                affiliationChanged      (3),
                superseded              (4),
                cessationOfOperation    (5),
                certificateHold         (6),
                privilegeWithdrawn      (7),
                aACompromise            (8) }
    */
    internal sealed class CrlDistributonPointsExtension : X509Extension
    {
        internal CrlDistributonPointsExtension(Uri uri)
            : base(TestOids.CrlDistributionPoints.Value, Encode(uri), critical: false)
        {
        }

        private static byte[] Encode(Uri uri)
        {
            AsnWriter writer = new(AsnEncodingRules.DER);

            using (writer.PushSequence()) // CRLDistributionPoints
            using (writer.PushSequence()) // DistributionPoint
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, tagValue: 0))) // GeneralNames
            {
                GeneralName generalName = new(uri: uri.OriginalString);

                generalName.Encode(writer);
            }

            return writer.Encode();
        }
    }
}

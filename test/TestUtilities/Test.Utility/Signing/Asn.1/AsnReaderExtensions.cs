// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Formats.Asn1;

namespace Test.Utility.Signing
{
    internal static class AsnReaderExtensions
    {
        internal static DateTimeOffset? ReadTime(this AsnReader reader)
        {
            if (reader is null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            if (reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime))
            {
                return reader.ReadUtcTime();
            }
            else if (reader.PeekTag().HasSameClassAndValue(Asn1Tag.GeneralizedTime))
            {
                return reader.ReadGeneralizedTime();
            }

            return null;
        }
    }
}

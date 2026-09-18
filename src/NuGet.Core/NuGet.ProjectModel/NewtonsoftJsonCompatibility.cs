// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#nullable disable

using System.Text.Encodings.Web;
using System.Text.Json;

namespace NuGet.ProjectModel
{
    internal static class NewtonsoftJsonCompatibility
    {
        internal static readonly JsonWriterOptions CompactWriterOptions = new()
        {
            Encoder = NewtonsoftCompatibleJavaScriptEncoder.Instance
        };

        internal static readonly JsonWriterOptions WriterOptions = new()
        {
            Encoder = NewtonsoftCompatibleJavaScriptEncoder.Instance,
            Indented = true,
#if NET9_0_OR_GREATER
            // Match Newtonsoft.Json's platform-specific newline behavior.
            NewLine = System.Environment.NewLine
#endif
        };

        private sealed class NewtonsoftCompatibleJavaScriptEncoder : JavaScriptEncoder
        {
            internal static readonly NewtonsoftCompatibleJavaScriptEncoder Instance = new();

            public override int MaxOutputCharactersPerInputCharacter => 6;

            public override unsafe int FindFirstCharacterToEncode(char* text, int textLength)
            {
                for (int index = 0; index < textLength; index++)
                {
                    if (WillEncode(text[index]))
                    {
                        return index;
                    }
                }

                return -1;
            }

            public override bool WillEncode(int unicodeScalar)
            {
                return unicodeScalar < ' '
                    || unicodeScalar == '"'
                    || unicodeScalar == '\\'
                    || unicodeScalar == 0x85
                    || unicodeScalar == 0x2028
                    || unicodeScalar == 0x2029
                    || unicodeScalar > 0x10FFFF;
            }

            public override unsafe bool TryEncodeUnicodeScalar(
                int unicodeScalar,
                char* buffer,
                int bufferLength,
                out int numberOfCharactersWritten)
            {
                char escapedCharacter = unicodeScalar switch
                {
                    '\b' => 'b',
                    '\t' => 't',
                    '\n' => 'n',
                    '\f' => 'f',
                    '\r' => 'r',
                    '"' => '"',
                    '\\' => '\\',
                    _ => '\0'
                };

                if (escapedCharacter != '\0')
                {
                    if (bufferLength < 2)
                    {
                        numberOfCharactersWritten = 0;
                        return false;
                    }

                    buffer[0] = '\\';
                    buffer[1] = escapedCharacter;
                    numberOfCharactersWritten = 2;
                    return true;
                }

                if (bufferLength < 6)
                {
                    numberOfCharactersWritten = 0;
                    return false;
                }

                const string HexadecimalDigits = "0123456789abcdef";
                buffer[0] = '\\';
                buffer[1] = 'u';
                buffer[2] = HexadecimalDigits[(unicodeScalar >> 12) & 0xf];
                buffer[3] = HexadecimalDigits[(unicodeScalar >> 8) & 0xf];
                buffer[4] = HexadecimalDigits[(unicodeScalar >> 4) & 0xf];
                buffer[5] = HexadecimalDigits[unicodeScalar & 0xf];
                numberOfCharactersWritten = 6;
                return true;
            }
        }
    }
}

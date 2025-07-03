// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
#if NET
using System.Diagnostics.CodeAnalysis;
#endif
using System.Runtime.InteropServices;

namespace NuGet.Packaging.Signing.Utility
{
    internal static class MarshalUtility
    {
        internal static T PtrToStructure<
#if NET
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.NonPublicConstructors)]
#endif
        T>(IntPtr pointer)
        {
            return Marshal.PtrToStructure<T>(pointer);
        }

        internal static int SizeOf<T>()
        {
            return Marshal.SizeOf<T>();
        }
    }
}

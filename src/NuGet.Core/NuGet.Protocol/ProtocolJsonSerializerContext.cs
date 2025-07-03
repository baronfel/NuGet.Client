// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Text.Json.Serialization;
using NuGet.Protocol.Model;

namespace NuGet.Protocol
{
    [JsonSourceGenerationOptions]
    [JsonSerializable(typeof(CaseInsensitiveDictionary<IReadOnlyList<PackageVulnerabilityInfo>>))]
    [JsonSerializable(typeof(IReadOnlyList<V3VulnerabilityIndexEntry>))]
    [JsonSerializable(typeof(V3VulnerabilityIndexEntry))]
    [JsonSerializable(typeof(HttpFileSystemBasedFindPackageByIdResource.FlatContainerVersionList))]
    internal partial class ProtocolJsonSerializerContext : JsonSerializerContext
    {
    }
}

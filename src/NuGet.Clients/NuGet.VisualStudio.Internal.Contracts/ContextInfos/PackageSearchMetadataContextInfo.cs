// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NuGet.Packaging;
using NuGet.Packaging.Core;
using NuGet.Protocol;
using NuGet.Protocol.Core.Types;
using static NuGet.Protocol.Core.Types.PackageSearchMetadataBuilder;

namespace NuGet.VisualStudio.Internal.Contracts
{
    public sealed class PackageSearchMetadataContextInfo : IPackageSearchMetadata
    {
        public PackageIdentity? Identity { get; internal set; }
        public string? Title { get; internal set; }
        public string? Description { get; internal set; }
        public string? Authors { get; internal set; }
        public Uri? IconUrl { get; internal set; }
        public string? Tags { get; internal set; }
        public Uri? LicenseUrl { get; internal set; }
        public Uri? ReadmeUrl { get; internal set; }
        public Uri? ProjectUrl { get; internal set; }
        public DateTimeOffset? Published { get; internal set; }
        public IReadOnlyList<string>? OwnersList { get; internal set; }
        public string? Owners { get; internal set; }
        private IOwnerDetailsUriService? _ownerDetailsUriService;
        public IReadOnlyList<KnownOwner> KnownOwners
        {
            get
            {
                if (_ownerDetailsUriService is null
                    || OwnersList is null
                    || OwnersList.Count == 0
                    || !_ownerDetailsUriService.SupportsKnownOwners)
                {
                    return Array.Empty<KnownOwner>();
                }

                List<KnownOwner> knownOwners = new(capacity: OwnersList.Count);

                foreach (string owner in OwnersList)
                {
                    Uri ownerDetailsUrl = _ownerDetailsUriService.GetOwnerDetailsUri(owner);
                    KnownOwner knownOwner = new(owner, ownerDetailsUrl);
                    knownOwners.Add(knownOwner);
                }

                return knownOwners;
            }
        }

        public Uri? ReportAbuseUrl { get; internal set; }
        public Uri? PackageDetailsUrl { get; internal set; }
        public bool RequireLicenseAcceptance { get; internal set; }
        public string? Summary { get; internal set; }
        public bool PrefixReserved { get; internal set; }
        public bool IsRecommended { get; internal set; }
        public (string modelVersion, string vsixVersion)? RecommenderVersion { get; internal set; }
        public bool IsListed { get; internal set; }
        public long? DownloadCount { get; internal set; }
        public IReadOnlyCollection<PackageDependencyGroup>? DependencySets { get; internal set; }
        public LicenseMetadata? LicenseMetadata { get; internal set; }
        public string? PackagePath { get; internal set; }
        public IReadOnlyCollection<PackageVulnerabilityMetadataContextInfo>? Vulnerabilities { get; internal set; }
        public IReadOnlyCollection<PackageIdentity>? TransitiveOrigins { get; internal set; }

        IEnumerable<PackageDependencyGroup> IPackageSearchMetadata.DependencySets => throw new NotImplementedException();

        IEnumerable<PackageVulnerabilityMetadata> IPackageSearchMetadata.Vulnerabilities => throw new NotImplementedException();

        public static PackageSearchMetadataContextInfo Create(IPackageSearchMetadata packageSearchMetadata)
        {
            return Create(packageSearchMetadata, isRecommended: false, recommenderVersion: null, ownerDetailsUriService: null);
        }

        public static PackageSearchMetadataContextInfo Create(IPackageSearchMetadata packageSearchMetadata, IOwnerDetailsUriService? ownerDetailsUriService)
        {
            return Create(packageSearchMetadata, isRecommended: false, recommenderVersion: null, ownerDetailsUriService);
        }

        public static PackageSearchMetadataContextInfo Create(IPackageSearchMetadata packageSearchMetadata, bool isRecommended, (string, string)? recommenderVersion, IOwnerDetailsUriService? ownerDetailsUriService)
        {
            return new PackageSearchMetadataContextInfo()
            {
                Title = packageSearchMetadata.Title,
                Description = packageSearchMetadata.Description,
                Authors = packageSearchMetadata.Authors,
                IconUrl = packageSearchMetadata.IconUrl,
                Tags = packageSearchMetadata.Tags,
                Identity = packageSearchMetadata.Identity,
                LicenseUrl = packageSearchMetadata.LicenseUrl,
                ReadmeUrl = packageSearchMetadata.ReadmeUrl,
                LicenseMetadata = packageSearchMetadata.LicenseMetadata,
                IsRecommended = isRecommended,
                RecommenderVersion = recommenderVersion,
                ProjectUrl = packageSearchMetadata.ProjectUrl,
                Published = packageSearchMetadata.Published,
                OwnersList = packageSearchMetadata.OwnersList,
                Owners = packageSearchMetadata.Owners,
                _ownerDetailsUriService = ownerDetailsUriService,
                ReportAbuseUrl = packageSearchMetadata.ReportAbuseUrl,
                PackageDetailsUrl = packageSearchMetadata.PackageDetailsUrl,
                PackagePath =
                    (packageSearchMetadata as LocalPackageSearchMetadata)?.PackagePath ??
                    (packageSearchMetadata as ClonedPackageSearchMetadata)?.PackagePath,
                RequireLicenseAcceptance = packageSearchMetadata.RequireLicenseAcceptance,
                Summary = packageSearchMetadata.Summary,
                PrefixReserved = packageSearchMetadata.PrefixReserved,
                IsListed = packageSearchMetadata.IsListed,
                DependencySets = packageSearchMetadata.DependencySets?.ToList(),
                DownloadCount = packageSearchMetadata.DownloadCount,
                Vulnerabilities = packageSearchMetadata.Vulnerabilities?
                    .Select(vulnerability => new PackageVulnerabilityMetadataContextInfo(vulnerability.AdvisoryUrl, vulnerability.Severity))
                    .OrderByDescending(v => v.Severity).ToArray(),
                TransitiveOrigins =
                    (packageSearchMetadata as TransitivePackageSearchMetadata)?.TransitiveOrigins,
            };
        }

        Task<PackageDeprecationMetadata> IPackageSearchMetadata.GetDeprecationMetadataAsync()
        {
            throw new NotImplementedException();
        }

        Task<IEnumerable<VersionInfo>> IPackageSearchMetadata.GetVersionsAsync()
        {
            throw new NotImplementedException();
        }
    }
}

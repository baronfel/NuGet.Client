using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using NuGet.Client;
using NuGet.Commands;
using NuGet.ContentModel;
using NuGet.Frameworks;
using NuGet.LibraryModel;
using NuGet.Packaging;
using NuGet.Packaging.Core;
using NuGet.ProjectModel;
using NuGet.Repositories;
using NuGet.RuntimeModel;
using NuGet.Versioning;

namespace Benchmarks
{
    [MemoryDiagnoser]
    public class Md5VsSha256
    {

        public readonly RuntimeGraph _runtimeGraph;
        public readonly NuGetv3LocalRepository _repository;
        NuGetFramework _framework = NuGetFramework.Parse("net9.0");
        ManagedCodeConventions _managedCodeConventions;
        LockFileBuilderCache _cache = new();
        List<(List<SelectionCriteria>, bool)> _orderedCriteria;

        public Md5VsSha256()
        {
            _runtimeGraph = new RuntimeGraph();
            _repository = new NuGetv3LocalRepository("E:\\.packages");
            _managedCodeConventions = new ManagedCodeConventions(_runtimeGraph);
            _cache = new();
            _orderedCriteria = LockFileUtils.CreateOrderedCriteriaSets(_managedCodeConventions, _framework, runtimeIdentifier: null);

        }

        [Benchmark]
        public void Sha256()
        {
            LocalPackageInfo package = _repository.FindPackage("newtonsoft.json", NuGetVersion.Parse("13.0.3"));
            ContentItemCollection contentItems = _cache.GetContentItems(null, package);

            LockFileLibrary library = LockFileBuilder.CreateLockFileLibrary(package, package.Sha512, package.ExpandedPath);
            LockFileTargetLibrary lockFileLib = new LockFileTargetLibrary()
            {
                Name = package.Id,
                Version = package.Version,
                Type = LibraryType.Package,
                PackageType = new List<PackageType>()
            };
            NuspecReader nuspecReader = package.Nuspec;

            LockFileUtils.AddAssets(
                null,
                library,
                package,
                _managedCodeConventions,
                LibraryIncludeFlags.All,
                lockFileLib,
                _framework,
                null,
                contentItems,
                nuspecReader,
                _orderedCriteria[0].Item1
                );
        }
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<Md5VsSha256>();
        }
    }
}

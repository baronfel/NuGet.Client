// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Build.Framework;
using Microsoft.Build.NuGetSdkResolver;
using NuGet.ProjectModel;

if (!AppContext.TryGetSwitch("NuGet.UseSystemTextJsonDeserialization", out bool isEnabled) || !isEnabled)
{
    return 1;
}

const string sdkName = "NuGet.AotCompatibility.Sdk";
const string sdkVersion = "1.2.3";
string testDirectory = Path.Combine(Path.GetTempPath(), "NuGet.AotCompatibility", Guid.NewGuid().ToString("N"));

try
{
    string projectDirectory = Path.Combine(testDirectory, "src");
    string packagesDirectory = Path.Combine(testDirectory, "packages");
    string packageDirectory = Path.Combine(packagesDirectory, sdkName.ToLowerInvariant(), sdkVersion);
    string expectedSdkPath = Path.Combine(packageDirectory, "Sdk");

    Directory.CreateDirectory(projectDirectory);
    Directory.CreateDirectory(expectedSdkPath);
    File.WriteAllText(
        Path.Combine(testDirectory, "global.json"),
        $$"""
        {
          // Verify that the streaming System.Text.Json reader accepts comments and trailing commas.
          "msbuild-sdks": {
            "{{sdkName}}": "{{sdkVersion}}",
          }
        }
        """);
    File.WriteAllText(
        Path.Combine(testDirectory, "NuGet.Config"),
        $$"""
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <config>
            <add key="globalPackagesFolder" value="{{packagesDirectory}}" />
          </config>
          <packageSources>
            <clear />
          </packageSources>
        </configuration>
        """);
    File.WriteAllText(
        Path.Combine(packageDirectory, $"{sdkName.ToLowerInvariant()}.{sdkVersion}.nupkg.sha512"),
        string.Empty);

    var resolver = new NuGetSdkResolver();
    var context = new SmokeTestSdkResolverContext(Path.Combine(projectDirectory, "SmokeTest.csproj"));
    var factory = new SmokeTestSdkResultFactory();
    SdkResult result = resolver.Resolve(
        new SdkReference(sdkName, version: null, minimumVersion: null),
        context,
        factory);

    if (!result.Success ||
        !string.Equals(result.Version, sdkVersion, StringComparison.Ordinal) ||
        !string.Equals(result.Path, expectedSdkPath, StringComparison.Ordinal))
    {
        Console.Error.WriteLine(
            $"Global.json SDK resolution failed. Success: {result.Success}; Version: {result.Version}; Path: {result.Path}");
        return 1;
    }

    const string packagesLockJson = """
        {
          "version": 3,
          "net10.0/win-x64": {
            "framework": "net10.0",
            "dependencies": {
              "PackageA": {
                "type": "Direct",
                "requested": "[1.0.0, )",
                "resolved": "1.2.3",
                "contentHash": "package-a-hash",
                "dependencies": {
                  "PackageB": "2.0.0"
                }
              },
              "PackageB": {
                "type": "Transitive",
                "resolved": "2.0.0",
                "contentHash": "package-b-hash"
              }
            }
          }
        }
        """;

    PackagesLockFile lockFile = PackagesLockFileFormat.Parse(packagesLockJson, "in-memory");
    if (lockFile.Version != 3 ||
        lockFile.Path != "in-memory" ||
        lockFile.Targets.Count != 1)
    {
        Console.Error.WriteLine("Package lock file metadata was not parsed.");
        return 1;
    }

    PackagesLockFileTarget target = lockFile.Targets[0];
    if (target.TargetAlias != "net10.0" ||
        target.RuntimeIdentifier != "win-x64" ||
        target.TargetFramework.GetShortFolderName() != "net10.0" ||
        target.Dependencies.Count != 2)
    {
        Console.Error.WriteLine("Package lock file target was not parsed.");
        return 1;
    }

    LockFileDependency packageA = target.Dependencies[0];
    if (packageA.Id != "PackageA" ||
        packageA.Type != PackageDependencyType.Direct ||
        packageA.RequestedVersion?.MinVersion?.ToNormalizedString() != "1.0.0" ||
        packageA.ResolvedVersion?.ToNormalizedString() != "1.2.3" ||
        packageA.ContentHash != "package-a-hash" ||
        packageA.Dependencies.Count != 1 ||
        packageA.Dependencies[0].Id != "PackageB" ||
        packageA.Dependencies[0].VersionRange?.MinVersion?.ToNormalizedString() != "2.0.0")
    {
        Console.Error.WriteLine("Package lock file dependency was not parsed.");
        return 1;
    }
}
finally
{
    if (Directory.Exists(testDirectory))
    {
        Directory.Delete(testDirectory, recursive: true);
    }
}

Console.WriteLine("Passed.");
return 0;

internal sealed class SmokeTestSdkResolverContext : SdkResolverContext
{
    internal SmokeTestSdkResolverContext(string projectFilePath)
    {
        ProjectFilePath = projectFilePath;
        Logger = new SmokeTestSdkLogger();
    }
}

internal sealed class SmokeTestSdkLogger : SdkLogger
{
    public override void LogMessage(string message, MessageImportance messageImportance = MessageImportance.Low)
    {
    }
}

internal sealed class SmokeTestSdkResultFactory : SdkResultFactory
{
    public override SdkResult IndicateFailure(IEnumerable<string> errors, IEnumerable<string>? warnings = null)
    {
        return new SmokeTestSdkResult(success: false, path: null, version: null);
    }

    public override SdkResult IndicateSuccess(string path, string version, IEnumerable<string>? warnings = null)
    {
        return new SmokeTestSdkResult(success: true, path, version);
    }
}

internal sealed class SmokeTestSdkResult : SdkResult
{
    internal SmokeTestSdkResult(bool success, string? path, string? version)
    {
        Success = success;
        Path = path;
        Version = version;
    }
}

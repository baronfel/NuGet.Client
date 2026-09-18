// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Microsoft.Build.Framework;
using Microsoft.Build.NuGetSdkResolver;
using NuGet.Frameworks;
using NuGet.Packaging.Core;
using NuGet.ProjectModel;
using NuGet.Versioning;

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

    if (RunPackageLockWriterSmoke(testDirectory) != 0)
    {
        return 1;
    }

    if (RunAssetsLockWriterSmoke(testDirectory) != 0)
    {
        return 1;
    }

    if (RunDependencyGraphSpecWriterSmoke(testDirectory, projectDirectory) != 0)
    {
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

static int RunPackageLockWriterSmoke(string testDirectory)
{
    var writerLockFile = new PackagesLockFile(PackagesLockFileFormat.PackagesLockFileVersion);
    var writerTarget = new PackagesLockFileTarget
    {
        TargetAlias = "net10.0",
        TargetFramework = NuGetFramework.Parse("net10.0")
    };
    var writerDependency = new LockFileDependency
    {
        Id = "Package.Direct",
        Type = PackageDependencyType.Direct,
        RequestedVersion = VersionRange.Parse("[1.0.0, 2.0.0)"),
        ResolvedVersion = NuGetVersion.Parse("1.2.3"),
        ContentHash = "café<&"
    };
    writerDependency.Dependencies.Add(new PackageDependency(
        "Package.Transitive",
        VersionRange.Parse("[2.0.0, )")));
    writerTarget.Dependencies.Add(writerDependency);
    writerLockFile.Targets.Add(writerTarget);

    string renderedOutput = PackagesLockFileFormat.Render(writerLockFile);

    var writerStream = new MemoryStream();
    PackagesLockFileFormat.Write(writerStream, writerLockFile);
    string streamOutput = Encoding.UTF8.GetString(writerStream.ToArray());

    string lockFileOutputPath = Path.Combine(testDirectory, "writer", PackagesLockFileFormat.LockFileName);
    PackagesLockFileFormat.Write(lockFileOutputPath, writerLockFile);
    string fileOutput = File.ReadAllText(lockFileOutputPath);

    if (!string.Equals(renderedOutput, streamOutput, StringComparison.Ordinal)
        || !string.Equals(renderedOutput, fileOutput, StringComparison.Ordinal)
        || !renderedOutput.Contains("\"version\": 3", StringComparison.Ordinal)
        || !renderedOutput.Contains("\"net10.0\": {", StringComparison.Ordinal)
        || !renderedOutput.Contains("\"Package.Direct\": {", StringComparison.Ordinal)
        || !renderedOutput.Contains("\"resolved\": \"1.2.3\"", StringComparison.Ordinal)
        || !renderedOutput.Contains("\"contentHash\": \"café<&\"", StringComparison.Ordinal)
        || !renderedOutput.Contains("\"Package.Transitive\":", StringComparison.Ordinal))
    {
        Console.Error.WriteLine("Package lock file writer output did not match.");
        return 1;
    }
    return 0;
}

static int RunAssetsLockWriterSmoke(string testDirectory)
{
    var lockFile = new LockFile
    {
        Version = LockFileFormat.Version,
        PackageSpec = new PackageSpec(new[]
        {
            new TargetFrameworkInformation
            {
                FrameworkName = NuGetFramework.Parse("net10.0"),
                TargetAlias = "net10.0"
            }
        })
    };
    var targetLibrary = new LockFileTargetLibrary
    {
        Name = "Package.Direct",
        Version = NuGetVersion.Parse("1.2.3"),
        Type = "package"
    };
    targetLibrary.Dependencies.Add(new PackageDependency(
        "Package.Transitive",
        VersionRange.Parse("[2.0.0, )")));
    targetLibrary.CompileTimeAssemblies.Add(new LockFileItem("lib/net10.0/Package.Direct.dll"));
    lockFile.Targets.Add(new LockFileTarget
    {
        TargetFramework = NuGetFramework.Parse("net10.0"),
        TargetAlias = "net10.0",
        Libraries = new[] { targetLibrary }
    });
    lockFile.Libraries.Add(new LockFileLibrary
    {
        Name = "Package.Direct",
        Version = NuGetVersion.Parse("1.2.3"),
        Type = "package",
        Sha512 = "café<&",
        Files = new[] { "lib/net10.0/Package.Direct.dll" }
    });
    lockFile.ProjectFileDependencyGroups.Add(
        new ProjectFileDependencyGroup("net10.0", new[] { "Package.Direct >= 1.2.3" }));

    var format = new LockFileFormat();
    string renderedOutput = format.Render(lockFile);

    var stream = new MemoryStream();
    format.Write(stream, lockFile);
    string streamOutput = Encoding.UTF8.GetString(stream.ToArray());

    string outputPath = Path.Combine(testDirectory, "writer", LockFileFormat.AssetsFileName);
    format.Write(outputPath, lockFile);
    string fileOutput = File.ReadAllText(outputPath);

    if (!string.Equals(renderedOutput, streamOutput, StringComparison.Ordinal)
        || !string.Equals(renderedOutput, fileOutput, StringComparison.Ordinal)
        || !renderedOutput.Contains("\"version\": 4", StringComparison.Ordinal)
        || !renderedOutput.Contains("\"targets\": {", StringComparison.Ordinal)
        || !renderedOutput.Contains("\"Package.Direct/1.2.3\": {", StringComparison.Ordinal)
        || !renderedOutput.Contains("\"sha512\": \"café<&\"", StringComparison.Ordinal)
        || !renderedOutput.Contains("\"project\": {", StringComparison.Ordinal))
    {
        Console.Error.WriteLine("Assets lock file writer output did not match.");
        return 1;
    }

    return 0;
}

static int RunDependencyGraphSpecWriterSmoke(string testDirectory, string projectDirectory)
{
    const string dependencyGraphProjectName = "Aot.Project-café-<&-\U0001F600";
    var dependencyGraphSpec = new DependencyGraphSpec();
    dependencyGraphSpec.AddRestore(dependencyGraphProjectName);
    dependencyGraphSpec.AddProject(new PackageSpec
    {
        Name = dependencyGraphProjectName,
        RestoreMetadata = new ProjectRestoreMetadata
        {
            ProjectName = dependencyGraphProjectName,
            ProjectPath = Path.Combine(projectDirectory, "Aot.Project.csproj"),
            ProjectUniqueName = dependencyGraphProjectName,
            ProjectStyle = ProjectStyle.PackageReference
        }
    });

    var dependencyGraphStream = new MemoryStream();
    dependencyGraphSpec.Save(dependencyGraphStream);
    string dependencyGraphStreamOutput = Encoding.UTF8.GetString(dependencyGraphStream.ToArray());

    string dependencyGraphOutputPath = Path.Combine(testDirectory, "writer", "Aot.Project.nuget.dgspec.json");
    dependencyGraphSpec.Save(dependencyGraphOutputPath);
    string dependencyGraphFileOutput = File.ReadAllText(dependencyGraphOutputPath);
    string dependencyGraphHash = dependencyGraphSpec.GetHash();
    string repeatedDependencyGraphHash = dependencyGraphSpec.GetHash();

    if (!string.Equals(dependencyGraphStreamOutput, dependencyGraphFileOutput, StringComparison.Ordinal)
        || !dependencyGraphStreamOutput.Contains("\"format\": 1", StringComparison.Ordinal)
        || !dependencyGraphStreamOutput.Contains($"\"{dependencyGraphProjectName}\": {{", StringComparison.Ordinal)
        || !dependencyGraphStreamOutput.Contains($"\"projectUniqueName\": \"{dependencyGraphProjectName}\"", StringComparison.Ordinal)
        || string.IsNullOrEmpty(dependencyGraphHash)
        || !string.Equals(dependencyGraphHash, repeatedDependencyGraphHash, StringComparison.Ordinal)
        || dependencyGraphStream.CanWrite)
    {
        Console.Error.WriteLine("Dependency graph writer output did not match.");
        return 1;
    }

    return 0;
}

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

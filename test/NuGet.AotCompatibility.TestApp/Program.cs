// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Microsoft.Build.Framework;
using Microsoft.Build.NuGetSdkResolver;
using NuGet.RuntimeModel;

if (!AppContext.TryGetSwitch("NuGet.UseSystemTextJsonDeserialization", out bool isEnabled) || !isEnabled)
{
    Console.Error.WriteLine("NuGet.UseSystemTextJsonDeserialization is not enabled.");
    return 1;
}

const string runtimeGraphJson = """
    {
      "runtimes": {
        "win-x64": {
          "#import": [ "win" ]
        }
      },
      "supports": {
        "desktop": {
          "net10.0": "win-x64"
        }
      }
    }
    """;

using var stream = new MemoryStream(Encoding.UTF8.GetBytes(runtimeGraphJson));
RuntimeGraph graph = JsonRuntimeFormat.ReadRuntimeGraph(stream);

if (!graph.Runtimes.TryGetValue("win-x64", out RuntimeDescription? runtime)
    || runtime.InheritedRuntimes.Count != 1
    || runtime.InheritedRuntimes[0] != "win")
{
    Console.Error.WriteLine("Runtime graph did not contain the expected win-x64 inheritance.");
    return 1;
}

if (!graph.Supports.TryGetValue("desktop", out CompatibilityProfile? profile)
    || profile.RestoreContexts.Count != 1
    || profile.RestoreContexts[0].RuntimeIdentifier != "win-x64")
{
    Console.Error.WriteLine("Runtime graph did not contain the expected desktop compatibility profile.");
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

    Console.WriteLine("Passed.");
    return 0;
}
finally
{
    if (Directory.Exists(testDirectory))
    {
        Directory.Delete(testDirectory, recursive: true);
    }
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

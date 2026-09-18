// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Newtonsoft.Json.Linq;
using NuGet.Common;
using NuGet.Frameworks;
using NuGet.Test.Utility;
using NuGet.Versioning;
using Xunit;

namespace NuGet.ProjectModel.Test
{
    public class PackagesLockFileFormatTests
    {
        [Fact]
        public void PackagesLockFileFormat_Read()
        {
            var nuGetLockFileContent = @"{
                ""version"": 1,
                ""dependencies"": {
                    "".NETFramework,Version=v4.5"": {
                        ""PackageA"": {
                            ""type"": ""Direct"",
                            ""requested"": ""[1.*, )"",
                            ""resolved"": ""1.0.0"",
                            ""contentHash"": ""sbWWhjA2/cXJHBBKAVo3m2U0KxzNuW5dQANDwx8L96V+L6SML96cM/Myvmp6fiBqIDibvF6+Ss9YC+qqclrXnw=="",
                            ""dependencies"": {
                                 ""PackageB"": ""1.0.0""
                            }
                        },
                        ""PackageB"": {
                            ""type"": ""Transitive"",
                            ""resolved"": ""1.0.0"",
                            ""contentHash"": ""Fjiywrwerewr4dgbdgbfgjkoiuiorwrwn24+8hjnnuerwrwsfsHYWD3HJYUI7NJHssxDFSFSFEWEW34DFDFCVsxv=="",
                        }
                    }
                }
            }";

            var lockFile = PackagesLockFileFormat.Parse(nuGetLockFileContent, "In Memory");

            Assert.Equal(1, lockFile.Targets.Count);

            var target = lockFile.Targets.First();
            Assert.Equal(".NETFramework,Version=v4.5", target.Name);
            Assert.Equal(2, target.Dependencies.Count);

            Assert.Equal("PackageA", target.Dependencies[0].Id);
            Assert.Equal(PackageDependencyType.Direct, target.Dependencies[0].Type);
            Assert.Equal("[1.*, )", target.Dependencies[0].RequestedVersion.ToNormalizedString());
            Assert.Equal("1.0.0", target.Dependencies[0].ResolvedVersion.ToNormalizedString());
            Assert.NotEmpty(target.Dependencies[0].ContentHash);
            Assert.Equal(1, target.Dependencies[0].Dependencies.Count);
            Assert.Equal("PackageB", target.Dependencies[0].Dependencies[0].Id);


            Assert.Equal("PackageB", target.Dependencies[1].Id);
            Assert.Equal(PackageDependencyType.Transitive, target.Dependencies[1].Type);
            Assert.Null(target.Dependencies[1].RequestedVersion);
            Assert.Equal("1.0.0", target.Dependencies[0].ResolvedVersion.ToNormalizedString());
            Assert.NotEmpty(target.Dependencies[1].ContentHash);
        }

        [Fact]
        public void PackagesLockFileFormat_ReadWithCommentsAndVersionAfterDependencies()
        {
            // Newtonsoft accepts comments, trailing commas, null dependency ranges, and a version property after dependencies.
            var lockFileContent = """
                {
                    // The version property is not required to be first.
                    "dependencies": {
                        "net8.0": {
                            "PackageA": {
                                "type": "Direct",
                                "resolved": "1.0.0",
                                "dependencies": {
                                    "PackageB": null,
                                },
                            },
                        },
                    },
                    "version": 1,
                }
                """;

            PackagesLockFile lockFile = ParseWithSystemTextJson(lockFileContent);

            Assert.Equal(1, lockFile.Version);
            var target = Assert.Single(lockFile.Targets);
            Assert.Equal(NuGetFramework.Parse("net8.0"), target.TargetFramework);
            var package = Assert.Single(target.Dependencies);
            Assert.Equal("PackageA", package.Id);
            Assert.Equal(VersionRange.All, Assert.Single(package.Dependencies).VersionRange);
        }

        [Fact]
        public void PackagesLockFileFormat_ReadVersion3WithVersionAfterTargets()
        {
            // Newtonsoft accepts the V3 version property after target properties.
            var lockFileContent = """
                {
                    "net8.0": {
                        "framework": "net8.0",
                        "dependencies": {
                            "PackageA": {
                                "type": "Direct",
                                "resolved": "1.0.0"
                            }
                        }
                    },
                    "version": 3
                }
                """;

            PackagesLockFile lockFile = ParseWithSystemTextJson(lockFileContent);

            Assert.Equal(3, lockFile.Version);
            var target = Assert.Single(lockFile.Targets);
            Assert.Equal("net8.0", target.TargetAlias);
            Assert.Equal("PackageA", Assert.Single(target.Dependencies).Id);
        }

        [Fact]
        public void PackagesLockFileFormat_ReadLockFileWithSystemTextJsonUtf8Bom_ParsesLockFile()
        {
            var stream = new MemoryStream();
            using (var writer = new StreamWriter(
                stream,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: true),
                bufferSize: 1024,
                leaveOpen: true))
            {
                writer.Write(@"{ ""version"": 1, ""dependencies"": {} }");
            }
            stream.Position = 0;

            PackagesLockFile lockFile = PackagesLockFileFormat.ReadLockFile(stream);

            // Package-lock stream reads historically take ownership of the input stream.
            Assert.False(stream.CanRead);
            Assert.Equal(1, lockFile.Version);
        }

        [Theory]
        [InlineData(1, false, false)]
        [InlineData(1, false, true)]
        [InlineData(1, true, false)]
        [InlineData(1, true, true)]
        [InlineData(2, false, false)]
        [InlineData(2, false, true)]
        [InlineData(2, true, false)]
        [InlineData(2, true, true)]
        public void PackagesLockFileFormat_ReadEncodedStream_ParsesAndDisposesSource(
            int encodingKind,
            bool bigEndian,
            bool useNonSeekableStream)
        {
            // StreamReader historically detected UTF-16/32 BOMs for both seekable and nonseekable package-lock streams.
            const string content = """{"version":1,"dependencies":{"net10.0":{}}}""";
            Encoding encoding = encodingKind switch
            {
                1 => new UnicodeEncoding(bigEndian, byteOrderMark: true),
                2 => new UTF32Encoding(bigEndian, byteOrderMark: true),
                _ => throw new ArgumentOutOfRangeException(nameof(encodingKind)),
            };
            byte[] preamble = encoding.GetPreamble();
            byte[] encodedContent = encoding.GetBytes(content);
            var bytes = new byte[preamble.Length + encodedContent.Length];
            Array.Copy(preamble, bytes, preamble.Length);
            Array.Copy(encodedContent, 0, bytes, preamble.Length, encodedContent.Length);
            Stream source = new MemoryStream(bytes);
            if (useNonSeekableStream)
            {
                source = new ChunkedReadStream(source, maxBytesPerRead: 1);
            }

            PackagesLockFile lockFile = PackagesLockFileFormat.Read(source, NullLogger.Instance, "encoded.lock.json");

            Assert.Equal(1, lockFile.Version);
            Assert.Equal(NuGetFramework.Parse("net10.0"), Assert.Single(lockFile.Targets).TargetFramework);
            // Package-lock stream reads historically dispose their source.
            Assert.False(source.CanRead);
        }

        [Fact]
        public void PackagesLockFileFormat_ReadLockFileWithSystemTextJsonLeadingTriviaLargerThanBuffer_ParsesLockFile()
        {
            // Newtonsoft accepts leading JSON whitespace regardless of its size.
            string content = new string(' ', 20_000) + """{"version":1,"dependencies":{}}""";

            PackagesLockFile lockFile = ParseWithSystemTextJson(content);

            Assert.Equal(1, lockFile.Version);
        }

        [Fact]
        public void PackagesLockFileFormat_ReadMalformedJson_LogsDiagnosticAndDisposesStream()
        {
            var stream = new MemoryStream(Encoding.UTF8.GetBytes("""{"version":1"""));
            var logger = new TestLogger();

            PackagesLockFile lockFile = PackagesLockFileFormat.Read(stream, logger, "broken.lock.json");

            // Malformed input historically logs information and returns an invalid-version sentinel instead of throwing.
            Assert.Equal(int.MinValue, lockFile.Version);
            Assert.Equal("broken.lock.json", lockFile.Path);
            Assert.False(stream.CanRead);
            Assert.Contains("broken.lock.json", Assert.Single(logger.InformationMessages));
        }

        [Fact]
        public void PackagesLockFileFormat_ReadWhenBomProbeThrows_ReturnsFallbackAndDisposesSource()
        {
            // StreamReader historically owns and disposes the source even when encoding detection fails.
            var stream = new ThrowingReadStream();
            var logger = new TestLogger();

            PackagesLockFile lockFile = PackagesLockFileFormat.Read(stream, logger, "unreadable.lock.json");

            Assert.Equal(int.MinValue, lockFile.Version);
            Assert.Equal("unreadable.lock.json", lockFile.Path);
            Assert.True(stream.IsDisposed);
            Assert.Contains("unreadable.lock.json", Assert.Single(logger.InformationMessages));
        }

        [Fact]
        public void PackagesLockFileFormat_ReadWithTextReader_ParsesAndDisposesReader()
        {
            var reader = new ThrowingReadToEndStringReader("""
                {
                  "version": 3,
                  "net10.0": {
                    "framework": "net10.0",
                    "dependencies": {
                      "PackageA": {
                        "type": "Direct",
                        "resolved": "1.2.3"
                      }
                    }
                  }
                }
                """);

#pragma warning disable CS0618 // Verify the retained compatibility API.
            PackagesLockFile lockFile = PackagesLockFileFormat.Read(reader, NullLogger.Instance, "text-reader.lock.json");
#pragma warning restore CS0618

            // The obsolete Newtonsoft path parses incrementally and historically owns the supplied TextReader.
            Assert.Equal("text-reader.lock.json", lockFile.Path);
            Assert.Equal("PackageA", Assert.Single(Assert.Single(lockFile.Targets).Dependencies).Id);
            Assert.Throws<ObjectDisposedException>(() => reader.Read());
        }

        [Fact]
        [UseCulture("fr-FR")]
        public void PackagesLockFileFormat_ReadNumericScalars_MatchesNewtonsoftJson()
        {
            // Newtonsoft normalizes JSON numeric values with invariant culture before package version parsing.
            const string content = """
                {
                  "version": 1.0,
                  "dependencies": {
                    "net10.0": {
                      "PackageA": {
                        "type": 1.0,
                        "requested": 1.10,
                        "resolved": 2.10,
                        "contentHash": 4.10,
                        "dependencies": {
                          "PackageB": 3.10
                        }
                      }
                    }
                  }
                }
                """;

            (PackagesLockFile legacy, PackagesLockFile streaming) = ReadWithBothReaders(content);

            // Newtonsoft coerces an integral floating-point root version to an integer.
            Assert.Equal(1, legacy.Version);
            Assert.Equal(legacy.Version, streaming.Version);

            LockFileDependency legacyPackage = Assert.Single(Assert.Single(legacy.Targets).Dependencies);
            LockFileDependency streamingPackage = Assert.Single(Assert.Single(streaming.Targets).Dependencies);
            // A numeric package type does not map to an enum name and retains the default value.
            Assert.Equal(PackageDependencyType.Transitive, legacyPackage.Type);
            Assert.Equal(legacyPackage.Type, streamingPackage.Type);
            Assert.NotNull(legacyPackage.RequestedVersion);
            Assert.NotNull(legacyPackage.RequestedVersion.MinVersion);
            // Newtonsoft normalizes numeric requested versions before VersionRange parsing.
            Assert.Equal("1.1.0", legacyPackage.RequestedVersion.MinVersion.ToNormalizedString());
            Assert.Equal(legacyPackage.RequestedVersion, streamingPackage.RequestedVersion);
            Assert.NotNull(legacyPackage.ResolvedVersion);
            // Newtonsoft normalizes numeric resolved versions before NuGetVersion parsing.
            Assert.Equal("2.1.0", legacyPackage.ResolvedVersion.ToNormalizedString());
            Assert.Equal(legacyPackage.ResolvedVersion, streamingPackage.ResolvedVersion);
            // Newtonsoft exposes numeric scalar fields using invariant normalized text.
            Assert.Equal("4.1", legacyPackage.ContentHash);
            Assert.Equal(legacyPackage.ContentHash, streamingPackage.ContentHash);

            NuGet.Packaging.Core.PackageDependency legacyDependency = Assert.Single(legacyPackage.Dependencies);
            NuGet.Packaging.Core.PackageDependency streamingDependency = Assert.Single(streamingPackage.Dependencies);
            Assert.NotNull(legacyDependency.VersionRange);
            Assert.NotNull(legacyDependency.VersionRange.MinVersion);
            // Newtonsoft normalizes numeric dependency ranges before VersionRange parsing.
            Assert.Equal("3.1.0", legacyDependency.VersionRange.MinVersion.ToNormalizedString());
            Assert.Equal(legacyDependency.VersionRange, streamingDependency.VersionRange);
        }

        [Fact]
        public void PackagesLockFileFormat_ReadTrailingContent_MatchesNewtonsoftJson()
        {
            // Newtonsoft stops after the first root object and ignores trailing content.
            const string content = """
                {
                  "version": 1,
                  "dependencies": {
                    "net10.0": {}
                  }
                }
                trailing content is ignored
                """;

            (PackagesLockFile legacy, PackagesLockFile streaming) = ReadWithBothReaders(content);

            Assert.Equal(1, legacy.Version);
            Assert.Equal(legacy.Version, streaming.Version);
            Assert.Equal(Assert.Single(legacy.Targets).TargetFramework, Assert.Single(streaming.Targets).TargetFramework);
        }

        [Fact]
        public void PackagesLockFileFormat_ReadLockFileWithSystemTextJsonDuplicateDependencies_UsesLastValue()
        {
            // JObject lookup preserves Newtonsoft's last-duplicate-wins behavior.
            const string content = """
                {
                    "version": 1,
                    "dependencies": {
                        "net8.0": {
                            "PackageA": null,
                            "PackageA": { "type": "Direct", "resolved": "2.0.0" }
                        }
                    }
                }
                """;

            PackagesLockFile lockFile = ParseWithSystemTextJson(content);

            LockFileDependency dependency = Assert.Single(Assert.Single(lockFile.Targets).Dependencies);
            Assert.Equal(NuGetVersion.Parse("2.0.0"), dependency.ResolvedVersion);
        }

        [Fact]
        public void PackagesLockFileFormat_ReadLockFileWithSystemTextJsonInvalidLastDuplicateTarget_IgnoresTarget()
        {
            // Newtonsoft uses the last duplicate target value, including an invalid value that removes the target.
            const string content = """
                {
                    "version": 3,
                    "net8.0": { "framework": "net8.0", "dependencies": {} },
                    "net8.0": null
                }
                """;

            PackagesLockFile lockFile = ParseWithSystemTextJson(content);

            Assert.Empty(lockFile.Targets);
        }

        [Fact]
        public void Read_VariousTargetFrameworksAndRuntimeIdentifiers_ParsedCorrectly()
        {
            // Arrange
            var lockFileContents =
@"{
    ""version"": 1,
    ""dependencies"": {
        "".NETFramework,Version=v4.7.2"": { },
        "".NETStandard,Version=v2.0"": { },
        "".NETCoreApp,Version=3.1"": { },
        "".NETCoreApp,Version=3.1/win-x64"": { },
        "".NETCoreApp,Version=5.0"": { },
        "".NETCoreApp,Version=5.0/win-x64"": { },
        ""net5.0-windows7.0"": { },
        ""net5.0-windows7.0/win-x64"": { },
        ""net6.0"": { },
        ""net6.0/win-x64"": { },
        ""net6.0-windows7.0"": { },
        ""net6.0-windows7.0/win-x64"": { },
    }
}";

            // Act
            var lockFile = PackagesLockFileFormat.Parse(lockFileContents, "In memory");

            // Assert
            Assert.Equal(12, lockFile.Targets.Count);

            Assert.Equal(FrameworkConstants.CommonFrameworks.Net472, lockFile.Targets[0].TargetFramework);
            Assert.Null(lockFile.Targets[0].RuntimeIdentifier);

            Assert.Equal(FrameworkConstants.CommonFrameworks.NetStandard20, lockFile.Targets[1].TargetFramework);
            Assert.Null(lockFile.Targets[1].RuntimeIdentifier);

            Assert.Equal(FrameworkConstants.CommonFrameworks.NetCoreApp31, lockFile.Targets[2].TargetFramework);
            Assert.Null(lockFile.Targets[2].RuntimeIdentifier);

            Assert.Equal(FrameworkConstants.CommonFrameworks.NetCoreApp31, lockFile.Targets[3].TargetFramework);
            Assert.Equal("win-x64", lockFile.Targets[3].RuntimeIdentifier);

            Assert.Equal(FrameworkConstants.CommonFrameworks.Net50, lockFile.Targets[4].TargetFramework);
            Assert.Null(lockFile.Targets[4].RuntimeIdentifier);

            Assert.Equal(FrameworkConstants.CommonFrameworks.Net50, lockFile.Targets[5].TargetFramework);
            Assert.Equal("win-x64", lockFile.Targets[5].RuntimeIdentifier);

            NuGetFramework net5win7 = NuGetFramework.Parse("net5.0-windows7.0");
            Assert.Equal(net5win7, lockFile.Targets[6].TargetFramework);
            Assert.Null(lockFile.Targets[6].RuntimeIdentifier);

            Assert.Equal(net5win7, lockFile.Targets[7].TargetFramework);
            Assert.Equal("win-x64", lockFile.Targets[7].RuntimeIdentifier);

            Assert.Equal(FrameworkConstants.CommonFrameworks.Net60, lockFile.Targets[8].TargetFramework);
            Assert.Null(lockFile.Targets[8].RuntimeIdentifier);

            Assert.Equal(FrameworkConstants.CommonFrameworks.Net60, lockFile.Targets[9].TargetFramework);
            Assert.Equal("win-x64", lockFile.Targets[9].RuntimeIdentifier);

            NuGetFramework net6win7 = NuGetFramework.Parse("net6.0-windows7.0");
            Assert.Equal(net6win7, lockFile.Targets[10].TargetFramework);
            Assert.Null(lockFile.Targets[10].RuntimeIdentifier);

            Assert.Equal(net6win7, lockFile.Targets[11].TargetFramework);
            Assert.Equal("win-x64", lockFile.Targets[11].RuntimeIdentifier);
        }

        [Fact]
        public void PackagesLockFileFormat_ReadWithRuntimeGraph()
        {
            var nuGetLockFileContent = @"{
                ""version"": 1,
                ""dependencies"": {
                    "".NETFramework,Version=v4.5"": {
                        ""PackageA"": {
                            ""type"": ""Direct"",
                            ""requested"": ""[1.*, )"",
                            ""resolved"": ""1.0.0"",
                            ""contentHash"": ""sbWWhjA2/cXJHBBKAVo3m2U0KxzNuW5dQANDwx8L96V+L6SML96cM/Myvmp6fiBqIDibvF6+Ss9YC+qqclrXnw=="",
                            ""dependencies"": {
                                 ""PackageB"": ""1.0.0""
                            }
                        },
                        ""PackageB"": {
                            ""type"": ""Transitive"",
                            ""resolved"": ""1.0.0"",
                            ""contentHash"": ""Fjiywrwerewr4dgbdgbfgjkoiuiorwrwn24+8hjnnuerwrwsfsHYWD3HJYUI7NJHssxDFSFSFEWEW34DFDFCVsxv==""
                        }
                    },
                    "".NETFramework,Version=v4.5/win10-arm"": {
                        ""PackageA"": {
                            ""type"": ""Direct"",
                            ""requested"": ""[1.*, )"",
                            ""resolved"": ""1.0.0"",
                            ""contentHash"": ""QuiokjhjA2/cXJHBBKAVo3m2U0KxzNuW5dQANDwx8L96V+L6SML96cM/Myvmp6fiBqIDibvF6+Ss9YC+qqcfwef=="",
                            ""dependencies"": {
                                 ""PackageB"": ""1.0.0"",
                                 ""runtime.win10-arm.PackageA"": ""1.0.0""
                            }
                        },
                        ""runtime.win10-arm.PackageA"": {
                            ""type"": ""Transitive"",
                            ""resolved"": ""1.0.0"",
                            ""contentHash"": ""dfgdgdfIY434jhjkhkRARFSZSGFSDG423452bgdnuerwrwsfsHYWD3HJYUI7NJHssxDFSFSFEWEW34DFjkyuerd=="",
                        }
                    }
                }
            }";

            var lockFile = PackagesLockFileFormat.Parse(nuGetLockFileContent, "In Memory");

            Assert.Equal(2, lockFile.Targets.Count);

            var target = lockFile.Targets.First(t => !string.IsNullOrEmpty(t.RuntimeIdentifier));
            Assert.Equal(".NETFramework,Version=v4.5/win10-arm", target.Name);
            Assert.Equal(2, target.Dependencies.Count);

            Assert.Equal("PackageA", target.Dependencies[0].Id);
            Assert.Equal(PackageDependencyType.Direct, target.Dependencies[0].Type);
            Assert.Equal("[1.*, )", target.Dependencies[0].RequestedVersion.ToNormalizedString());
            Assert.Equal("1.0.0", target.Dependencies[0].ResolvedVersion.ToNormalizedString());
            Assert.NotEmpty(target.Dependencies[0].ContentHash);
            Assert.Equal(2, target.Dependencies[0].Dependencies.Count);
            Assert.Equal("PackageB", target.Dependencies[0].Dependencies[0].Id);
            Assert.Equal("runtime.win10-arm.PackageA", target.Dependencies[0].Dependencies[1].Id);

            // Runtime graph will only have additional transitive dependenies which are not part of
            // original TFM graph
            Assert.Equal("runtime.win10-arm.PackageA", target.Dependencies[1].Id);
            Assert.Equal(PackageDependencyType.Transitive, target.Dependencies[1].Type);
            Assert.Null(target.Dependencies[1].RequestedVersion);
            Assert.Equal("1.0.0", target.Dependencies[0].ResolvedVersion.ToNormalizedString());
            Assert.NotEmpty(target.Dependencies[1].ContentHash);
        }

        [Fact]
        public void PackagesLockFileFormat_Write()
        {
            var nuGetLockFileContent = @"{
                ""version"": 1,
                ""dependencies"": {
                    "".NETFramework,Version=v4.5"": {
                        ""PackageA"": {
                            ""type"": ""Direct"",
                            ""requested"": ""[1.*, )"",
                            ""resolved"": ""1.0.0"",
                            ""contentHash"": ""sbWWhjA2/cXJHBBKAVo3m2U0KxzNuW5dQANDwx8L96V+L6SML96cM/Myvmp6fiBqIDibvF6+Ss9YC+qqclrXnw=="",
                            ""dependencies"": {
                                 ""PackageB"": ""1.0.0""
                            }
                        },
                        ""PackageB"": {
                            ""type"": ""Transitive"",
                            ""resolved"": ""1.0.0"",
                            ""contentHash"": ""Fjiywrwerewr4dgbdgbfgjkoiuiorwrwn24+8hjnnuerwrwsfsHYWD3HJYUI7NJHssxDFSFSFEWEW34DFDFCVsxv=="",
                        }
                    }
                }
            }";

            var lockFile = PackagesLockFileFormat.Parse(nuGetLockFileContent, "In Memory");
            var output = PackagesLockFileFormat.Render(lockFile);
            // JObject.ToString() pins the legacy property order, indentation, and platform newline.
            var expected = JObject.Parse(nuGetLockFileContent).ToString();

            Assert.Equal(expected, output);
        }

        [Fact]
        public void PackagesLockFileFormat_WritePublicApis_PreserveNewtonsoftOutput()
        {
            const string lockFileContent = """
                {
                  "version": 2,
                  "dependencies": {
                    "net8.0": {
                      "ProjectA": {
                        "type": "Project",
                        "resolved": "1.0.0",
                        "contentHash": "café<&",
                        "dependencies": {
                          "PackageB": "[1.0.0, 2.0.0)"
                        }
                      }
                    }
                  }
                }
                """;
            PackagesLockFile lockFile = PackagesLockFileFormat.Parse(lockFileContent, "In Memory");
            string expected = JObject.Parse(lockFileContent).ToString();
            string filePath = Path.GetTempFileName();

            try
            {
                string renderedOutput = PackagesLockFileFormat.Render(lockFile);

                var stream = new MemoryStream();
                PackagesLockFileFormat.Write(stream, lockFile);
                // Write historically owns the stream; ToArray still exposes its exact legacy bytes after disposal.
                string streamOutput = Encoding.UTF8.GetString(stream.ToArray());

                PackagesLockFileFormat.Write(filePath, lockFile);
                string fileOutput = File.ReadAllText(filePath);

                Assert.Equal(expected, renderedOutput);
                Assert.Equal(expected, streamOutput);
                Assert.Equal(expected, fileOutput);
            }
            finally
            {
                File.Delete(filePath);
            }
        }

        [Fact]
        public void PackagesLockFileFormat_WriteTextWriter_UsesLegacyNewtonsoftWriter()
        {
            const string lockFileContent = """
                {
                  "version": 1,
                  "dependencies": {
                    "net8.0": {
                      "PackageA": {
                        "type": "Direct",
                        "contentHash": "café<&"
                      }
                    }
                  }
                }
                """;
            PackagesLockFile lockFile = PackagesLockFileFormat.Parse(lockFileContent, "In Memory");
            string expected = JObject.Parse(lockFileContent).ToString();
            var writer = new StringWriter();

            // This shipped overload intentionally remains the Newtonsoft compatibility path.
            PackagesLockFileFormat.Write(writer, lockFile);

            Assert.Equal(expected, writer.ToString());
        }

        // Newtonsoft emits ordinary Unicode and HTML-sensitive characters verbatim,
        // uses lowercase escapes for controls and separators, and JSON-escapes quotes and backslashes.
        [Theory]
        [InlineData("emoji-\U0001F600")]
        [InlineData("delete-\u007F")]
        [InlineData("next-line-\u0085")]
        [InlineData("line-separator-\u2028")]
        [InlineData("paragraph-separator-\u2029")]
        [InlineData("controls-\u0000\u0001\b\t\n\f\r\u001F")]
        [InlineData("Latin-café-Ångström")]
        [InlineData("html-<>&'")]
        [InlineData("quote-\"-backslash-\\")]
        public void PackagesLockFileFormat_WriteEscaping_MatchesNewtonsoft(string value)
        {
            PackagesLockFile lockFile = CreateLockFileWithValue(value);

            var legacyWriter = new StringWriter();
            PackagesLockFileFormat.Write(legacyWriter, lockFile);

            string output = PackagesLockFileFormat.Render(lockFile);

            Assert.Equal(legacyWriter.ToString(), output);
        }

        [Fact]
        public void PackagesLockFileFormat_RenderMalformedUtf16_MatchesNewtonsoft()
        {
            foreach (string malformedText in GetMalformedUtf16Values())
            {
                PackagesLockFile lockFile = CreateLockFileWithValue(malformedText);
                AssertMalformedUtf16RenderMatchesNewtonsoft(lockFile);
            }
        }

        [Theory]
        [InlineData("requested")]
        [InlineData("resolved")]
        [InlineData("projectDependency")]
        [InlineData("packageDependency")]
        public void PackagesLockFileFormat_RenderMalformedVersionStrings_MatchNewtonsoft(string field)
        {
            // Version formatters can preserve lone surrogate code units in release labels.
            foreach (string malformedText in GetMalformedUtf16Values())
            {
                PackagesLockFile lockFile = CreateLockFileWithMalformedVersion(field, malformedText);
                AssertMalformedUtf16RenderMatchesNewtonsoft(lockFile);
            }
        }

        [Fact]
        public void PackagesLockFileFormat_WriteMalformedUtf16_DoesNotUseTextWriterFallback()
        {
            foreach (string malformedText in GetMalformedUtf16Values())
            {
                PackagesLockFile lockFile = CreateLockFileWithValue(malformedText);
                var stream = new MemoryStream();

                PackagesLockFileFormat.Write(stream, lockFile);
                string actual = Encoding.UTF8.GetString(stream.ToArray());

                Assert.NotNull(JObject.Parse(actual));
                Assert.False(stream.CanWrite);
            }
        }

        [Fact]
        public void PackagesLockFileFormat_WriteDuplicateTargets_DoesNotWriteToStream()
        {
            var lockFile = new PackagesLockFile(1);
            lockFile.Targets.Add(new PackagesLockFileTarget { TargetFramework = NuGetFramework.Parse("net8.0") });
            lockFile.Targets.Add(new PackagesLockFileTarget { TargetFramework = NuGetFramework.Parse("net8.0") });

            AssertDuplicateWriteIsAtomic(lockFile, "net8.0");
        }

        [Fact]
        public void PackagesLockFileFormat_WriteDuplicatePackages_DoesNotWriteToStream()
        {
            var lockFile = new PackagesLockFile(1);
            var target = new PackagesLockFileTarget { TargetFramework = NuGetFramework.Parse("net8.0") };
            target.Dependencies.Add(new LockFileDependency { Id = "PackageA" });
            target.Dependencies.Add(new LockFileDependency { Id = "PackageA" });
            lockFile.Targets.Add(target);

            AssertDuplicateWriteIsAtomic(lockFile, "PackageA");
        }

        [Fact]
        public void PackagesLockFileFormat_WriteDuplicateDependencies_DoesNotWriteToStream()
        {
            var lockFile = new PackagesLockFile(1);
            var target = new PackagesLockFileTarget { TargetFramework = NuGetFramework.Parse("net8.0") };
            var package = new LockFileDependency { Id = "PackageA" };
            package.Dependencies.Add(new NuGet.Packaging.Core.PackageDependency("PackageB"));
            package.Dependencies.Add(new NuGet.Packaging.Core.PackageDependency("PackageB"));
            target.Dependencies.Add(package);
            lockFile.Targets.Add(target);

            AssertDuplicateWriteIsAtomic(lockFile, "PackageB");
        }

        [Fact]
        public void PackagesLockFileFormat_WriteVersion3TargetNamedVersion_DoesNotWriteToStream()
        {
            var lockFile = new PackagesLockFile(3);
            lockFile.Targets.Add(new PackagesLockFileTarget
            {
                TargetAlias = "version",
                TargetFramework = NuGetFramework.Parse("net8.0")
            });

            AssertDuplicateWriteIsAtomic(lockFile, "version");
        }

        [Fact]
        public void PackagesLockFileFormat_WriteNullTarget_DoesNotWriteToStream()
        {
            var lockFile = new PackagesLockFile(1);
            lockFile.Targets.Add(null);

            AssertNullNameWriteIsAtomic(lockFile);
        }

        [Fact]
        public void PackagesLockFileFormat_WriteNullPackageNameAfterLargeContent_DoesNotWriteToStream()
        {
            // The legacy DOM validated all property names before flushing any preceding content.
            var lockFile = new PackagesLockFile(1);
            var target = new PackagesLockFileTarget { TargetFramework = NuGetFramework.Parse("net8.0") };
            target.Dependencies.Add(new LockFileDependency
            {
                Id = "LargePackage",
                ContentHash = new string('a', 100_000)
            });
            target.Dependencies.Add(new LockFileDependency { Id = null });
            lockFile.Targets.Add(target);

            AssertNullNameWriteIsAtomic(lockFile);
        }

        [Fact]
        public void PackagesLockFileFormat_WriteNullDependency_DoesNotWriteToStream()
        {
            var lockFile = new PackagesLockFile(1);
            var target = new PackagesLockFileTarget { TargetFramework = NuGetFramework.Parse("net8.0") };
            var package = new LockFileDependency { Id = "PackageA" };
            package.Dependencies.Add(null);
            target.Dependencies.Add(package);
            lockFile.Targets.Add(target);

            AssertNullNameWriteIsAtomic(lockFile);
        }

        [Fact]
        public void PackagesLockFileFormat_ReadVersion3WithAliases()
        {
            var lockFileContent = @"{
                ""version"": 3,
                ""netcoreapp10.0"": {
                    ""framework"": ""net10.0"",
                    ""dependencies"": {
                        ""PackageA"": {
                            ""type"": ""Direct"",
                            ""requested"": ""[1.0.0, )"",
                            ""resolved"": ""1.0.0"",
                            ""contentHash"": ""hash1""
                        }
                    }
                },
                ""net10.0"": {
                    ""framework"": ""net10.0"",
                    ""dependencies"": {
                        ""PackageB"": {
                            ""type"": ""Direct"",
                            ""requested"": ""[2.0.0, )"",
                            ""resolved"": ""2.0.0"",
                            ""contentHash"": ""hash2""
                        }
                    }
                }
            }";

            var lockFile = PackagesLockFileFormat.Parse(lockFileContent, "In Memory");

            Assert.Equal(3, lockFile.Version);
            Assert.Equal(2, lockFile.Targets.Count);

            var target1 = lockFile.Targets[0];
            Assert.Equal("netcoreapp10.0", target1.TargetAlias);
            Assert.Equal(NuGetFramework.Parse("net10.0"), target1.TargetFramework);
            Assert.Equal("PackageA", target1.Dependencies[0].Id);

            var target2 = lockFile.Targets[1];
            Assert.Equal("net10.0", target2.TargetAlias);
            Assert.Equal(NuGetFramework.Parse("net10.0"), target2.TargetFramework);
            Assert.Equal("PackageB", target2.Dependencies[0].Id);
        }

        [Fact]
        public void PackagesLockFileFormat_ReadVersion3WithAliasesAndRid()
        {
            var lockFileContent = @"{
                ""version"": 3,
                ""netcoreapp10.0"": {
                    ""framework"": ""net10.0"",
                    ""dependencies"": {
                        ""PackageA"": {
                            ""type"": ""Direct"",
                            ""resolved"": ""1.0.0"",
                            ""contentHash"": ""hash1""
                        }
                    }
                },
                ""netcoreapp10.0/win-x64"": {
                    ""framework"": ""net10.0"",
                    ""dependencies"": {
                        ""PackageC"": {
                            ""type"": ""Transitive"",
                            ""resolved"": ""1.5.0"",
                            ""contentHash"": ""hash3""
                        }
                    }
                }
            }";

            var lockFile = PackagesLockFileFormat.Parse(lockFileContent, "In Memory");

            Assert.Equal(3, lockFile.Version);
            Assert.Equal(2, lockFile.Targets.Count);

            var target1 = lockFile.Targets[0];
            Assert.Equal("netcoreapp10.0", target1.TargetAlias);
            Assert.Equal(NuGetFramework.Parse("net10.0"), target1.TargetFramework);
            Assert.Null(target1.RuntimeIdentifier);

            var target2 = lockFile.Targets[1];
            Assert.Equal("netcoreapp10.0", target2.TargetAlias);
            Assert.Equal(NuGetFramework.Parse("net10.0"), target2.TargetFramework);
            Assert.Equal("win-x64", target2.RuntimeIdentifier);
        }

        [Fact]
        public void PackagesLockFileFormat_WriteVersion3WithAliases()
        {
            var lockFile = new PackagesLockFile(3);

            var target1 = new PackagesLockFileTarget
            {
                TargetFramework = NuGetFramework.Parse("net10.0"),
                TargetAlias = "netcoreapp10.0"
            };
            target1.Dependencies.Add(new LockFileDependency
            {
                Id = "PackageA",
                Type = PackageDependencyType.Direct,
                ResolvedVersion = NuGetVersion.Parse("1.0.0"),
                ContentHash = "hash1"
            });

            var target2 = new PackagesLockFileTarget
            {
                TargetFramework = NuGetFramework.Parse("net10.0"),
                TargetAlias = "net10.0"
            };
            target2.Dependencies.Add(new LockFileDependency
            {
                Id = "PackageB",
                Type = PackageDependencyType.Direct,
                ResolvedVersion = NuGetVersion.Parse("2.0.0"),
                ContentHash = "hash2"
            });

            lockFile.Targets.Add(target1);
            lockFile.Targets.Add(target2);

            var output = PackagesLockFileFormat.Render(lockFile);
            var json = JObject.Parse(output);

            Assert.Equal(3, (int)json["version"]!);
            Assert.True(json.ContainsKey("netcoreapp10.0"));
            Assert.True(json.ContainsKey("net10.0"));

            var target1Json = json["netcoreapp10.0"] as JObject;
            Assert.NotNull(target1Json);
            Assert.Equal("net10.0", (string)target1Json["framework"]!);
            Assert.NotNull(target1Json["dependencies"]);

            var target2Json = json["net10.0"] as JObject;
            Assert.NotNull(target2Json);
            Assert.Equal("net10.0", (string)target2Json["framework"]!);
            Assert.NotNull(target2Json["dependencies"]);
        }

        [Fact]
        public void PackagesLockFileFormat_RoundTripVersion3WithAliases()
        {
            var originalContent = @"{
                ""version"": 3,
                ""netcoreapp10.0"": {
                    ""framework"": ""net10.0"",
                    ""dependencies"": {
                        ""PackageA"": {
                            ""type"": ""Direct"",
                            ""resolved"": ""1.0.0"",
                            ""contentHash"": ""hash1""
                        }
                    }
                },
                ""net10.0"": {
                    ""framework"": ""net10.0"",
                    ""dependencies"": {
                        ""PackageB"": {
                            ""type"": ""Direct"",
                            ""resolved"": ""2.0.0"",
                            ""contentHash"": ""hash2""
                        }
                    }
                }
            }";

            var lockFile = PackagesLockFileFormat.Parse(originalContent, "In Memory");
            var output = PackagesLockFileFormat.Render(lockFile);
            // Preserve the legacy textual shape, not only semantic JSON equivalence.
            var expected = JObject.Parse(originalContent).ToString();

            Assert.Equal(expected, output);
        }

        [Fact]
        public void PackagesLockFileFormat_BackwardCompatibilityVersion1()
        {
            var v1Content = @"{
                ""version"": 1,
                ""dependencies"": {
                    "".NETFramework,Version=v4.7.2"": {
                        ""PackageA"": {
                            ""type"": ""Direct"",
                            ""resolved"": ""1.0.0"",
                            ""contentHash"": ""hash1""
                        }
                    }
                }
            }";

            var lockFile = PackagesLockFileFormat.Parse(v1Content, "In Memory");

            Assert.Equal(1, lockFile.Version);
            Assert.Equal(1, lockFile.Targets.Count);
            Assert.Null(lockFile.Targets[0].TargetAlias);
            Assert.Equal(NuGetFramework.Parse(".NETFramework,Version=v4.7.2"), lockFile.Targets[0].TargetFramework);
        }

        [Fact]
        public void PackagesLockFileFormat_BackwardCompatibilityVersion2()
        {
            var v2Content = @"{
                ""version"": 2,
                ""dependencies"": {
                    ""net6.0"": {
                        ""PackageA"": {
                            ""type"": ""Direct"",
                            ""resolved"": ""1.0.0"",
                            ""contentHash"": ""hash1""
                        }
                    }
                }
            }";

            var lockFile = PackagesLockFileFormat.Parse(v2Content, "In Memory");

            Assert.Equal(2, lockFile.Version);
            Assert.Equal(1, lockFile.Targets.Count);
            Assert.Null(lockFile.Targets[0].TargetAlias);
        }

        private static PackagesLockFile ParseWithSystemTextJson(string content)
        {
            var stream = new MemoryStream(Encoding.UTF8.GetBytes(content));
            return PackagesLockFileFormat.ReadLockFile(stream);
        }

        private static (PackagesLockFile Legacy, PackagesLockFile Streaming) ReadWithBothReaders(string content)
        {
#pragma warning disable CS0618 // Compare the retained compatibility API with the streaming replacement.
            PackagesLockFile legacy = PackagesLockFileFormat.Read(
                new StringReader(content),
                NullLogger.Instance,
                "legacy");
#pragma warning restore CS0618
            PackagesLockFile streaming = PackagesLockFileFormat.Read(
                new MemoryStream(Encoding.UTF8.GetBytes(content)),
                NullLogger.Instance,
                "streaming");

            return (legacy, streaming);
        }

        private sealed class ThrowingReadToEndStringReader : StringReader
        {
            internal ThrowingReadToEndStringReader(string value)
                : base(value)
            {
            }

            public override string ReadToEnd()
            {
                throw new InvalidOperationException("The compatibility path must not buffer the complete TextReader input as a string.");
            }
        }

        private sealed class ChunkedReadStream : Stream
        {
            private readonly Stream _stream;
            private readonly int _maxBytesPerRead;

            internal ChunkedReadStream(Stream stream, int maxBytesPerRead)
            {
                _stream = stream;
                _maxBytesPerRead = maxBytesPerRead;
            }

            public override bool CanRead => _stream.CanRead;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                return _stream.Read(buffer, offset, Math.Min(count, _maxBytesPerRead));
            }

            public override void Flush()
            {
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _stream.Dispose();
                }

                base.Dispose(disposing);
            }

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }

        private sealed class ThrowingReadStream : Stream
        {
            internal bool IsDisposed { get; private set; }

            public override bool CanRead => !IsDisposed;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new IOException("The source cannot be read.");
            }

            public override void Flush()
            {
            }

            protected override void Dispose(bool disposing)
            {
                IsDisposed = true;
                base.Dispose(disposing);
            }

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }

        private static void AssertDuplicateWriteIsAtomic(PackagesLockFile lockFile, string propertyName)
        {
            var stream = new MemoryStream();

            // The legacy DOM writer rejected duplicate properties before emitting bytes.
            ArgumentException exception = Assert.Throws<ArgumentException>(
                () => PackagesLockFileFormat.Write(stream, lockFile));

            // Preserve the useful duplicate name, zero-byte failure, and caller-stream ownership.
            Assert.Contains(propertyName, exception.Message);
            Assert.Empty(stream.ToArray());
            Assert.False(stream.CanWrite);
        }

        private static void AssertNullNameWriteIsAtomic(PackagesLockFile lockFile)
        {
            var stream = new MemoryStream();

            ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
                () => PackagesLockFileFormat.Write(stream, lockFile));

            Assert.Equal("name", exception.ParamName);
            Assert.Empty(stream.ToArray());
            Assert.False(stream.CanWrite);
        }

        private static PackagesLockFile CreateLockFileWithValue(string value)
        {
            var lockFile = new PackagesLockFile(3);
            var target = new PackagesLockFileTarget
            {
                TargetAlias = $"target-{value}",
                TargetFramework = NuGetFramework.Parse("net8.0")
            };
            var package = new LockFileDependency
            {
                Id = $"package-{value}",
                Type = PackageDependencyType.Direct,
                ContentHash = value
            };
            package.Dependencies.Add(new NuGet.Packaging.Core.PackageDependency($"dependency-{value}"));
            target.Dependencies.Add(package);
            lockFile.Targets.Add(target);
            return lockFile;
        }

        private static PackagesLockFile CreateLockFileWithMalformedVersion(
            string field,
            string malformedText)
        {
            var version = new NuGetVersion(1, 0, 0, $"bad-{malformedText}");
            var lockFile = new PackagesLockFile(3);
            var target = new PackagesLockFileTarget
            {
                TargetAlias = "net8.0",
                TargetFramework = NuGetFramework.Parse("net8.0")
            };
            var package = new LockFileDependency
            {
                Id = "PackageA",
                Type = field == "projectDependency"
                    ? PackageDependencyType.Project
                    : PackageDependencyType.Direct
            };

            switch (field)
            {
                case "requested":
                    package.RequestedVersion = new VersionRange(version);
                    break;
                case "resolved":
                    package.ResolvedVersion = version;
                    break;
                case "projectDependency":
                case "packageDependency":
                    package.Dependencies.Add(
                        new NuGet.Packaging.Core.PackageDependency("PackageB", new VersionRange(version)));
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(field));
            }

            target.Dependencies.Add(package);
            lockFile.Targets.Add(target);
            return lockFile;
        }

        private static void AssertMalformedUtf16RenderMatchesNewtonsoft(PackagesLockFile lockFile)
        {
            var legacyWriter = new StringWriter();
            PackagesLockFileFormat.Write(legacyWriter, lockFile);

            string renderedOutput = PackagesLockFileFormat.Render(lockFile);

            Assert.Equal(legacyWriter.ToString(), renderedOutput);
        }

        private static IEnumerable<string> GetMalformedUtf16Values()
        {
            yield return "\uD800";
            yield return "\uDC00";
            yield return "\uD800x";
        }

    }
}

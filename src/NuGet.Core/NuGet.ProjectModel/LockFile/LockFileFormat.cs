// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#nullable disable

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Newtonsoft.Json;
using NuGet.Common;
using NuGet.Packaging.Core;
using NuGet.RuntimeModel;
using NuGet.Versioning;

namespace NuGet.ProjectModel
{
    /// <summary>
    /// Reads and writes the <c>project.assets.json</c> file used by restore consumers.
    /// </summary>
    public class LockFileFormat
    {
        /// <summary>
        /// The current assets file format version.
        /// </summary>
        public static readonly int Version = 4;

        /// <summary>
        /// The assets file version that uses target aliases instead of framework names for multi-targeted projects.
        /// </summary>
        public const int AliasedVersion = 4;

        /// <summary>
        /// The assets file version used by classic projects and SDK versions earlier than 10.0.300.
        /// </summary>
        public const int LegacyVersion = 3;

        // If this is ever renamed, you should also rename NoOpRestoreUtilities.NoOpCacheFileName to keep them in sync.
        /// <summary>
        /// The standard assets file name.
        /// </summary>
        public static readonly string AssetsFileName = "project.assets.json";

        private const string VersionProperty = "version";
        private const string LibrariesProperty = "libraries";
        private const string TargetsProperty = "targets";
        private const string ProjectFileDependencyGroupsProperty = "projectFileDependencyGroups";
        private const string ServicableProperty = "servicable";
        private const string Sha512Property = "sha512";
        private const string FilesProperty = "files";
        private const string HasToolsProperty = "hasTools";
        private const string DependenciesProperty = "dependencies";
        private const string FrameworkAssembliesProperty = "frameworkAssemblies";
        private const string RuntimeProperty = "runtime";
        private const string CompileProperty = "compile";
        private const string AnalyzersProperty = "analyzers";
        private const string NativeProperty = "native";
        private const string BuildProperty = "build";
        private const string BuildMultiTargetingProperty = "buildMultiTargeting";
        private const string ContentFilesProperty = "contentFiles";
        private const string RuntimeTargetsProperty = "runtimeTargets";
        private const string ResourceProperty = "resource";
        private const string TypeProperty = "type";
        private const string PathProperty = "path";
        private const string MSBuildProjectProperty = "msbuildProject";
        private const string FrameworkProperty = "framework";
        private const string ToolsProperty = "tools";
        private const string PackageFoldersProperty = "packageFolders";
        private const string PackageSpecProperty = "project";
        internal const string LogsProperty = "logs";
        private const string EmbedProperty = "embed";
        private const string FrameworkReferencesProperty = "frameworkReferences";
        private const string CentralTransitiveDependencyGroupsProperty = "centralTransitiveDependencyGroups";

        private const int StackallocCharThreshold = 256;
        private static readonly JsonWriterOptions WriterOptions = new()
        {
            Indented = true
        };

        private static ReadOnlySpan<byte> VersionPropertyUtf8 => "version"u8;
        private static ReadOnlySpan<byte> LibrariesPropertyUtf8 => "libraries"u8;
        private static ReadOnlySpan<byte> TargetsPropertyUtf8 => "targets"u8;
        private static ReadOnlySpan<byte> ProjectFileDependencyGroupsPropertyUtf8 => "projectFileDependencyGroups"u8;
        private static ReadOnlySpan<byte> ServicablePropertyUtf8 => "servicable"u8;
        private static ReadOnlySpan<byte> Sha512PropertyUtf8 => "sha512"u8;
        private static ReadOnlySpan<byte> FilesPropertyUtf8 => "files"u8;
        private static ReadOnlySpan<byte> HasToolsPropertyUtf8 => "hasTools"u8;
        private static ReadOnlySpan<byte> DependenciesPropertyUtf8 => "dependencies"u8;
        private static ReadOnlySpan<byte> FrameworkAssembliesPropertyUtf8 => "frameworkAssemblies"u8;
        private static ReadOnlySpan<byte> RuntimePropertyUtf8 => "runtime"u8;
        private static ReadOnlySpan<byte> CompilePropertyUtf8 => "compile"u8;
        private static ReadOnlySpan<byte> AnalyzersPropertyUtf8 => "analyzers"u8;
        private static ReadOnlySpan<byte> NativePropertyUtf8 => "native"u8;
        private static ReadOnlySpan<byte> BuildPropertyUtf8 => "build"u8;
        private static ReadOnlySpan<byte> BuildMultiTargetingPropertyUtf8 => "buildMultiTargeting"u8;
        private static ReadOnlySpan<byte> ContentFilesPropertyUtf8 => "contentFiles"u8;
        private static ReadOnlySpan<byte> RuntimeTargetsPropertyUtf8 => "runtimeTargets"u8;
        private static ReadOnlySpan<byte> ResourcePropertyUtf8 => "resource"u8;
        private static ReadOnlySpan<byte> TypePropertyUtf8 => "type"u8;
        private static ReadOnlySpan<byte> PathPropertyUtf8 => "path"u8;
        private static ReadOnlySpan<byte> MSBuildProjectPropertyUtf8 => "msbuildProject"u8;
        private static ReadOnlySpan<byte> FrameworkPropertyUtf8 => "framework"u8;
        private static ReadOnlySpan<byte> ToolsPropertyUtf8 => "tools"u8;
        private static ReadOnlySpan<byte> PackageFoldersPropertyUtf8 => "packageFolders"u8;
        private static ReadOnlySpan<byte> PackageSpecPropertyUtf8 => "project"u8;
        private static ReadOnlySpan<byte> LogsPropertyUtf8 => "logs"u8;
        private static ReadOnlySpan<byte> EmbedPropertyUtf8 => "embed"u8;
        private static ReadOnlySpan<byte> FrameworkReferencesPropertyUtf8 => "frameworkReferences"u8;
        private static ReadOnlySpan<byte> CentralTransitiveDependencyGroupsPropertyUtf8 => "centralTransitiveDependencyGroups"u8;
        private static ReadOnlySpan<byte> LogCodePropertyUtf8 => "code"u8;
        private static ReadOnlySpan<byte> LogLevelPropertyUtf8 => "level"u8;
        private static ReadOnlySpan<byte> LogWarningLevelPropertyUtf8 => "warningLevel"u8;
        private static ReadOnlySpan<byte> LogFilePathPropertyUtf8 => "filePath"u8;
        private static ReadOnlySpan<byte> LogStartLineNumberPropertyUtf8 => "startLineNumber"u8;
        private static ReadOnlySpan<byte> LogStartColumnNumberPropertyUtf8 => "startColumnNumber"u8;
        private static ReadOnlySpan<byte> LogEndLineNumberPropertyUtf8 => "endLineNumber"u8;
        private static ReadOnlySpan<byte> LogEndColumnNumberPropertyUtf8 => "endColumnNumber"u8;
        private static ReadOnlySpan<byte> LogMessagePropertyUtf8 => "message"u8;
        private static ReadOnlySpan<byte> LogLibraryIdPropertyUtf8 => "libraryId"u8;
        private static ReadOnlySpan<byte> LogTargetGraphsPropertyUtf8 => "targetGraphs"u8;

        /// <summary>
        /// Parses complete assets file content and uses <paramref name="path"/> in diagnostics.
        /// </summary>
        /// <remarks>
        /// This method allocates a UTF-8 copy of the complete string. Use a stream overload to avoid the copy.
        /// </remarks>
        public LockFile Parse(string lockFileContent, string path)
        {
            return Parse(lockFileContent, NullLogger.Instance, path);
        }

        /// <summary>
        /// Parses complete assets file content and logs parsing failures.
        /// </summary>
        /// <remarks>
        /// This method allocates a UTF-8 copy of the complete string. Use a stream overload to avoid the copy.
        /// </remarks>
        public LockFile Parse(string lockFileContent, ILogger log, string path)
        {
            byte[] byteArray = Encoding.UTF8.GetBytes(lockFileContent);
            using (var stream = new MemoryStream(byteArray))
            {
                return Read(stream, log, path);
            }
        }

        /// <summary>
        /// Reads an assets file and returns an invalid lock file when parsing fails.
        /// </summary>
        public LockFile Read(string filePath)
        {
            return Read(filePath, NullLogger.Instance);
        }

        /// <summary>
        /// Reads an assets file and logs parsing failures.
        /// </summary>
        public LockFile Read(string filePath, ILogger log)
        {
            using (var stream = File.OpenRead(filePath))
            {
                return Read(stream, log, filePath);
            }
        }

        /// <summary>
        /// Reads UTF-8 assets data without disposing the source stream.
        /// </summary>
        /// <remarks>
        /// The caller retains ownership of <paramref name="stream"/>. Parsing starts at the current stream position.
        /// </remarks>
        public LockFile Read(Stream stream, string path)
        {
            return Read(stream, NullLogger.Instance, path);
        }

#pragma warning disable CA1822 // Mark members as static - public API
        /// <summary>
        /// Reads UTF-8 assets data, logs failures, and does not dispose the source stream.
        /// </summary>
        /// <remarks>
        /// The caller retains ownership of <paramref name="stream"/>. Parsing starts at the current stream position.
        /// </remarks>
        public LockFile Read(Stream stream, ILogger log, string path)
#pragma warning restore CA1822 // Mark members as static
        {
            return Read(stream, log, path, flags: LockFileReadFlags.All);
        }

        internal static LockFile Read(Stream stream, ILogger log, string path, LockFileReadFlags flags)
        {
            return Utf8JsonRead(stream, log, path, flags);
        }

        /// <summary>
        /// Creates the parent directory and replaces an existing assets file.
        /// </summary>
        /// <param name="filePath">The destination assets file path.</param>
        /// <param name="lockFile">The assets file model to write.</param>
        /// <remarks>
        /// This method writes directly to the destination file. A writing failure can leave partial output.
        /// </remarks>
        public void Write(string filePath, LockFile lockFile)
        {
            // Create the directory if it does not exist
            var fileInfo = new FileInfo(filePath);
            fileInfo.Directory.Create();

            using (var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                Write(stream, lockFile);
            }
        }

#pragma warning disable CA1822 // Mark members as static - public API
        /// <summary>
        /// Writes UTF-8 assets data and disposes the destination stream before returning.
        /// </summary>
        /// <param name="stream">The destination stream. This method takes ownership of the stream.</param>
        /// <param name="lockFile">The assets file model to write.</param>
        /// <remarks>
        /// This method writes incrementally through a pooled buffer. A writing failure can leave partial output.
        /// </remarks>
        public void Write(Stream stream, LockFile lockFile)
#pragma warning restore CA1822 // Mark members as static
        {
            using (stream)
            {
                WriteToStream(stream, lockFile);
            }
        }

        /// <summary>
        /// Uses the legacy Newtonsoft.Json writer and disposes the destination text writer.
        /// </summary>
        /// <param name="textWriter">The destination text writer. This method takes ownership of the writer.</param>
        /// <param name="lockFile">The assets file model to write.</param>
        /// <remarks>
        /// A writing failure can leave partial output. Use a stream overload for native System.Text.Json writing
        /// and NativeAOT compatibility.
        /// </remarks>
        [Obsolete("Use Write(Stream, LockFile) instead for native System.Text.Json writing and NativeAOT compatibility.")]
        public void Write(TextWriter textWriter, LockFile lockFile)
        {
            using (var jsonWriter = new JsonTextWriter(textWriter))
            using (var jsonObjectWriter = new JsonObjectWriter(jsonWriter))
            {
                jsonWriter.Formatting = Formatting.Indented;

                WriteLockFile(jsonWriter, jsonObjectWriter, lockFile);
            }
        }

#pragma warning disable CA1822 // Mark members as static
        /// <summary>
        /// Renders the complete assets file as a string.
        /// </summary>
        /// <remarks>
        /// This method buffers the complete UTF-8 output before it creates the returned UTF-16 string.
        /// </remarks>
        /// <param name="lockFile">The assets file model to render.</param>
        /// <returns>The rendered assets file.</returns>
        [Obsolete("Use Write(Stream, LockFile) instead to avoid buffering the entire lock file in memory.")]
        public string Render(LockFile lockFile)
#pragma warning restore CA1822 // Mark members as static
        {
            using (var stream = new MemoryStream())
            {
                WriteToStream(stream, lockFile);
                return Encoding.UTF8.GetString(stream.GetBuffer(), 0, checked((int)stream.Length));
            }
        }

        private static LockFile Utf8JsonRead(Stream stream, ILogger log, string path, LockFileReadFlags flags)
        {
            try
            {
                var lockFile = JsonUtility.LoadJson(stream, Utf8JsonStreamLockFileConverters.LockFileConverter, flags);
                lockFile.Path = path;
                return lockFile;
            }
            catch (Exception ex)
            {
                log.LogError(string.Format(CultureInfo.CurrentCulture,
                    Strings.Log_ErrorReadingLockFile,
                    path, ex.Message));

                // Ran into parsing errors, mark it as unlocked and out-of-date
                return new LockFile
                {
                    Version = int.MinValue,
                    Path = path
                };
            }
        }

        private static void WriteToStream(Stream stream, LockFile lockFile)
        {
            using (var bufferWriter = new PooledStreamBufferWriter(stream))
            using (var writer = new Utf8JsonWriter(bufferWriter, WriterOptions))
            {
                WriteLockFile(writer, lockFile);
                writer.Flush();
                bufferWriter.Flush();
            }
        }

        private static void WriteLockFile(Utf8JsonWriter writer, LockFile lockFile)
        {
            var objectWriter = new Utf8JsonObjectWriter(writer);

            writer.WriteStartObject();
            writer.WriteNumber(VersionPropertyUtf8, lockFile.Version);

            writer.WritePropertyName(TargetsPropertyUtf8);
            WriteObject(writer, lockFile.Targets, WriteTarget);

            writer.WritePropertyName(LibrariesPropertyUtf8);
            WriteObject(writer, lockFile.Libraries, WriteLibrary);

            writer.WritePropertyName(ProjectFileDependencyGroupsPropertyUtf8);
            WriteObject(writer, lockFile.ProjectFileDependencyGroups, WriteProjectFileDependencyGroup);

            if (lockFile.PackageFolders?.Any() == true)
            {
                writer.WritePropertyName(PackageFoldersPropertyUtf8);
                WriteObject(writer, lockFile.PackageFolders, WriteFileItem);
            }

            if (lockFile.Version >= 2 && lockFile.PackageSpec != null)
            {
                writer.WritePropertyName(PackageSpecPropertyUtf8);
                writer.WriteStartObject();

                PackageSpecWriter.Write(
                    lockFile.PackageSpec,
                    objectWriter,
                    hashing: false,
                    EnvironmentVariableWrapper.Instance,
                    useLegacyWriter: lockFile.Version <= LegacyVersion);

                writer.WriteEndObject();
            }

            if (lockFile.Version >= 3 && lockFile.LogMessages.Count > 0)
            {
                string projectPath = lockFile.PackageSpec?.RestoreMetadata?.ProjectPath;
                writer.WritePropertyName(LogsPropertyUtf8);
                WriteLogMessages(writer, lockFile.LogMessages, projectPath);
            }

            if (lockFile.CentralTransitiveDependencyGroups.Any())
            {
                writer.WritePropertyName(CentralTransitiveDependencyGroupsPropertyUtf8);
                WriteCentralTransitiveDependencyGroup(objectWriter, lockFile.CentralTransitiveDependencyGroups);
            }

            writer.WriteEndObject();
        }

        private static void WriteLibrary(Utf8JsonWriter writer, LockFileLibrary library)
        {
            WriteLibraryPropertyName(writer, library.Name, library.Version);
            writer.WriteStartObject();

            if (library.IsServiceable)
            {
                writer.WriteBoolean(ServicablePropertyUtf8, library.IsServiceable);
            }

            if (library.Sha512 != null)
            {
                writer.WriteString(Sha512PropertyUtf8, library.Sha512);
            }

            writer.WriteString(TypePropertyUtf8, library.Type);

            if (library.Path != null)
            {
                writer.WriteString(PathPropertyUtf8, library.Path);
            }

            if (library.MSBuildProject != null)
            {
                writer.WriteString(MSBuildProjectPropertyUtf8, library.MSBuildProject);
            }

            if (library.HasTools)
            {
                writer.WriteBoolean(HasToolsPropertyUtf8, library.HasTools);
            }

            WritePathArray(writer, FilesPropertyUtf8, library.Files);
            writer.WriteEndObject();
        }

        private static void WriteTarget(Utf8JsonWriter writer, LockFileTarget target)
        {
            writer.WritePropertyName(target.Name);
            WriteObject(writer, target.Libraries, WriteTargetLibrary);
        }

        private static void WriteLogMessage(Utf8JsonWriter writer, IAssetsLogMessage logMessage, string projectPath)
        {
            writer.WriteStartObject();
            writer.WriteString(LogCodePropertyUtf8, Enum.GetName(typeof(NuGetLogCode), logMessage.Code));
            writer.WriteString(LogLevelPropertyUtf8, Enum.GetName(typeof(LogLevel), logMessage.Level));

            if (logMessage.Level == LogLevel.Warning)
            {
                writer.WriteNumber(LogWarningLevelPropertyUtf8, (int)logMessage.WarningLevel);
            }

            if (logMessage.FilePath != null &&
                (projectPath == null || !PathUtility.GetStringComparerBasedOnOS().Equals(logMessage.FilePath, projectPath)))
            {
                writer.WriteString(LogFilePathPropertyUtf8, logMessage.FilePath);
            }

            if (logMessage.StartLineNumber > 0)
            {
                writer.WriteNumber(LogStartLineNumberPropertyUtf8, logMessage.StartLineNumber);
            }

            if (logMessage.StartColumnNumber > 0)
            {
                writer.WriteNumber(LogStartColumnNumberPropertyUtf8, logMessage.StartColumnNumber);
            }

            if (logMessage.EndLineNumber > 0)
            {
                writer.WriteNumber(LogEndLineNumberPropertyUtf8, logMessage.EndLineNumber);
            }

            if (logMessage.EndColumnNumber > 0)
            {
                writer.WriteNumber(LogEndColumnNumberPropertyUtf8, logMessage.EndColumnNumber);
            }

            if (logMessage.Message != null)
            {
                writer.WriteString(LogMessagePropertyUtf8, logMessage.Message);
            }

            if (logMessage.LibraryId != null)
            {
                writer.WriteString(LogLibraryIdPropertyUtf8, logMessage.LibraryId);
            }

            if (logMessage.TargetGraphs != null &&
                logMessage.TargetGraphs.Any() &&
                logMessage.TargetGraphs.All(targetGraph => !string.IsNullOrEmpty(targetGraph)))
            {
                writer.WritePropertyName(LogTargetGraphsPropertyUtf8);
                WriteArray(writer, logMessage.TargetGraphs);
            }

            writer.WriteEndObject();
        }

        private static void WriteLogMessages(Utf8JsonWriter writer, IEnumerable<IAssetsLogMessage> logMessages, string projectPath)
        {
            writer.WriteStartArray();

            foreach (IAssetsLogMessage logMessage in logMessages)
            {
                WriteLogMessage(writer, logMessage, projectPath);
            }

            writer.WriteEndArray();
        }

        private static void WriteTargetLibrary(Utf8JsonWriter writer, LockFileTargetLibrary library)
        {
            WriteLibraryPropertyName(writer, library.Name, library.Version);
            writer.WriteStartObject();

            if (library.Type != null)
            {
                writer.WriteString(TypePropertyUtf8, library.Type);
            }

            if (library.Framework != null)
            {
                writer.WriteString(FrameworkPropertyUtf8, library.Framework);
            }

            if (library.Dependencies.Count > 0)
            {
                IEnumerable<PackageDependency> ordered = library.Dependencies.OrderBy(
                    dependency => dependency.Id,
                    StringComparer.Ordinal);

                writer.WritePropertyName(DependenciesPropertyUtf8);
                WriteObject(writer, ordered, WritePackageDependencyWithLegacyString);
            }

            if (library.FrameworkAssemblies.Count > 0)
            {
                IEnumerable<string> ordered = library.FrameworkAssemblies.OrderBy(
                    assembly => assembly,
                    StringComparer.Ordinal);

                writer.WritePropertyName(FrameworkAssembliesPropertyUtf8);
                WriteArray(writer, ordered);
            }

            WriteItems(writer, CompilePropertyUtf8, library.CompileTimeAssemblies);
            WriteItems(writer, AnalyzersPropertyUtf8, library.AnalyzerAssets);
            WriteItems(writer, RuntimePropertyUtf8, library.RuntimeAssemblies);

            if (library.FrameworkReferences.Count > 0)
            {
                IEnumerable<string> ordered = library.FrameworkReferences.OrderBy(
                    reference => reference,
                    StringComparer.Ordinal);

                writer.WritePropertyName(FrameworkReferencesPropertyUtf8);
                WriteArray(writer, ordered);
            }

            WriteItems(writer, ResourcePropertyUtf8, library.ResourceAssemblies);
            WriteItems(writer, NativePropertyUtf8, library.NativeLibraries);
            WriteItems(writer, ContentFilesPropertyUtf8, library.ContentFiles);
            WriteItems(writer, BuildPropertyUtf8, library.Build);
            WriteItems(writer, BuildMultiTargetingPropertyUtf8, library.BuildMultiTargeting);
            WriteItems(writer, RuntimeTargetsPropertyUtf8, library.RuntimeTargets);
            WriteItems(writer, ToolsPropertyUtf8, library.ToolsAssemblies);
            WriteItems(writer, EmbedPropertyUtf8, library.EmbedAssemblies);

            writer.WriteEndObject();
        }

        private static void WriteItems<T>(Utf8JsonWriter writer, ReadOnlySpan<byte> propertyName, IList<T> items)
            where T : LockFileItem
        {
            if (items.Count > 0)
            {
                IEnumerable<LockFileItem> ordered = items.OrderBy(
                    item => item.Path,
                    StringComparer.Ordinal);

                writer.WritePropertyName(propertyName);
                WriteObject(writer, ordered, WriteFileItem);
            }
        }

        private static void WriteProjectFileDependencyGroup(
            Utf8JsonWriter writer,
            ProjectFileDependencyGroup frameworkInfo)
        {
            writer.WritePropertyName(frameworkInfo.FrameworkName);
            WriteArray(writer, frameworkInfo.Dependencies);
        }

        private static void WriteFileItem(Utf8JsonWriter writer, LockFileItem item)
        {
            writer.WritePropertyName(item.Path);
            writer.WriteStartObject();

            foreach (KeyValuePair<string, string> property in item.Properties.OrderBy(
                property => property.Key,
                StringComparer.Ordinal))
            {
                if (bool.TrueString.Equals(property.Value, StringComparison.OrdinalIgnoreCase))
                {
                    writer.WriteBoolean(property.Key, true);
                }
                else if (bool.FalseString.Equals(property.Value, StringComparison.OrdinalIgnoreCase))
                {
                    writer.WriteBoolean(property.Key, false);
                }
                else
                {
                    writer.WriteString(property.Key, property.Value);
                }
            }

            writer.WriteEndObject();
        }

        private static void WritePathArray(Utf8JsonWriter writer, ReadOnlySpan<byte> property, IEnumerable<string> items)
        {
            using var itemsEnumerator = items.NoAllocEnumerate().GetEnumerator();
            if (itemsEnumerator.MoveNext())
            {
                IEnumerable<string> orderedItems = items
                    .Select(GetPathWithForwardSlashes)
                    .OrderBy(item => item, StringComparer.Ordinal);

                writer.WritePropertyName(property);
                WriteArray(writer, orderedItems);
            }
        }

        private static void WritePackageDependencyWithLegacyString(
            Utf8JsonWriter writer,
            PackageDependency dependency)
        {
            writer.WritePropertyName(dependency.Id);
            writer.WriteStringValue(dependency.VersionRange?.ToNonSnapshotRange().ToLegacyShortString());
        }

        private static void WriteLibraryPropertyName(Utf8JsonWriter writer, string name, NuGetVersion version)
        {
            string normalizedVersion = version.ToNormalizedString();
            int propertyNameLength = name.Length + 1 + normalizedVersion.Length;
            char[] rentedBuffer = null;
            Span<char> propertyName = propertyNameLength <= StackallocCharThreshold
                ? stackalloc char[StackallocCharThreshold]
                : (rentedBuffer = ArrayPool<char>.Shared.Rent(propertyNameLength));

            try
            {
                name.AsSpan().CopyTo(propertyName);
                propertyName[name.Length] = '/';
                normalizedVersion.AsSpan().CopyTo(propertyName.Slice(name.Length + 1));
                writer.WritePropertyName(propertyName.Slice(0, propertyNameLength));
            }
            finally
            {
                if (rentedBuffer != null)
                {
                    ArrayPool<char>.Shared.Return(rentedBuffer);
                }
            }
        }

        private static void WriteArray(Utf8JsonWriter writer, IEnumerable<string> values)
        {
            writer.WriteStartArray();

            foreach (string value in values)
            {
                writer.WriteStringValue(value);
            }

            writer.WriteEndArray();
        }

        private static void WriteObject<T>(
            Utf8JsonWriter writer,
            IEnumerable<T> items,
            Action<Utf8JsonWriter, T> writeItem)
        {
            writer.WriteStartObject();

            foreach (T item in items)
            {
                writeItem(writer, item);
            }

            writer.WriteEndObject();
        }

        private static void WriteLockFile(JsonWriter writer, IObjectWriter jsonObjectWriter, LockFile lockFile)
        {
            writer.WriteStartObject();

            writer.WritePropertyName(VersionProperty);
            writer.WriteValue(lockFile.Version);

            writer.WritePropertyName(TargetsProperty);
            JsonUtility.WriteObject(writer, lockFile.Targets, WriteTarget);

            writer.WritePropertyName(LibrariesProperty);
            JsonUtility.WriteObject(writer, lockFile.Libraries, WriteLibrary);

            writer.WritePropertyName(ProjectFileDependencyGroupsProperty);
            JsonUtility.WriteObject(writer, lockFile.ProjectFileDependencyGroups, WriteProjectFileDependencyGroup);

            if (lockFile.PackageFolders?.Any() == true)
            {
                writer.WritePropertyName(PackageFoldersProperty);
                JsonUtility.WriteObject(writer, lockFile.PackageFolders, WriteFileItem);
            }

            if (lockFile.Version >= 2)
            {
                if (lockFile.PackageSpec != null)
                {
                    writer.WritePropertyName(PackageSpecProperty);

                    jsonObjectWriter.WriteObjectStart();

                    PackageSpecWriter.Write(lockFile.PackageSpec, jsonObjectWriter, hashing: false, EnvironmentVariableWrapper.Instance, useLegacyWriter: lockFile.Version <= LegacyVersion);

                    jsonObjectWriter.WriteObjectEnd();
                }
            }

            if (lockFile.Version >= 3)
            {
                if (lockFile.LogMessages.Count > 0)
                {
                    var projectPath = lockFile.PackageSpec?.RestoreMetadata?.ProjectPath;
                    writer.WritePropertyName(LogsProperty);
                    WriteLogMessages(writer, lockFile.LogMessages, projectPath);
                }
            }

            if (lockFile.CentralTransitiveDependencyGroups.Any())
            {
                writer.WritePropertyName(CentralTransitiveDependencyGroupsProperty);
                WriteCentralTransitiveDependencyGroup(jsonObjectWriter, lockFile.CentralTransitiveDependencyGroups);
            }

            writer.WriteEndObject();
        }

        private static void WriteLibrary(JsonWriter writer, LockFileLibrary library)
        {
            writer.WritePropertyName(library.Name + "/" + library.Version.ToNormalizedString());

            writer.WriteStartObject();

            if (library.IsServiceable)
            {
                writer.WritePropertyName(ServicableProperty);
                writer.WriteValue(library.IsServiceable);
            }

            if (library.Sha512 != null)
            {
                writer.WritePropertyName(Sha512Property);
                writer.WriteValue(library.Sha512);
            }

            writer.WritePropertyName(TypeProperty);
            writer.WriteValue(library.Type);

            if (library.Path != null)
            {
                writer.WritePropertyName(PathProperty);
                writer.WriteValue(library.Path);
            }

            if (library.MSBuildProject != null)
            {
                writer.WritePropertyName(MSBuildProjectProperty);
                writer.WriteValue(library.MSBuildProject);
            }

            if (library.HasTools)
            {
                writer.WritePropertyName(HasToolsProperty);
                writer.WriteValue(library.HasTools);
            }

            WritePathArray(writer, FilesProperty, library.Files);

            writer.WriteEndObject();
        }

        private static void WriteTarget(JsonWriter writer, LockFileTarget target)
        {
            var key = target.Name;

            writer.WritePropertyName(key);

            JsonUtility.WriteObject(writer, target.Libraries, WriteTargetLibrary);
        }

        /// <summary>
        /// Writes the <see cref="IAssetsLogMessage"/> object to the <see cref="JsonWriter"/>.
        /// </summary>
        /// <param name="logMessage"><code>IAssetsLogMessage</code> representing the log message.</param>
        private static void WriteLogMessage(JsonWriter writer, IAssetsLogMessage logMessage, string projectPath)
        {
            writer.WriteStartObject();

            writer.WritePropertyName(LogMessageProperties.CODE);
            writer.WriteValue(Enum.GetName(typeof(NuGetLogCode), logMessage.Code));

            writer.WritePropertyName(LogMessageProperties.LEVEL);
            writer.WriteValue(Enum.GetName(typeof(LogLevel), logMessage.Level));

            if (logMessage.Level == LogLevel.Warning)
            {
                writer.WritePropertyName(LogMessageProperties.WARNING_LEVEL);
                writer.WriteValue((int)logMessage.WarningLevel);
            }

            if (logMessage.FilePath != null &&
               (projectPath == null || !PathUtility.GetStringComparerBasedOnOS().Equals(logMessage.FilePath, projectPath)))
            {
                // Do not write the file path if it is the same as the project path.
                // This prevents duplicate information in the lock file.
                writer.WritePropertyName(LogMessageProperties.FILE_PATH);
                writer.WriteValue(logMessage.FilePath);
            }

            if (logMessage.StartLineNumber > 0)
            {
                writer.WritePropertyName(LogMessageProperties.START_LINE_NUMBER);
                writer.WriteValue(logMessage.StartLineNumber);
            }

            if (logMessage.StartColumnNumber > 0)
            {
                writer.WritePropertyName(LogMessageProperties.START_COLUMN_NUMBER);
                writer.WriteValue(logMessage.StartColumnNumber);
            }

            if (logMessage.EndLineNumber > 0)
            {
                writer.WritePropertyName(LogMessageProperties.END_LINE_NUMBER);
                writer.WriteValue(logMessage.EndLineNumber);
            }

            if (logMessage.EndColumnNumber > 0)
            {
                writer.WritePropertyName(LogMessageProperties.END_COLUMN_NUMBER);
                writer.WriteValue(logMessage.EndColumnNumber);
            }

            if (logMessage.Message != null)
            {
                writer.WritePropertyName(LogMessageProperties.MESSAGE);
                writer.WriteValue(logMessage.Message);
            }

            if (logMessage.LibraryId != null)
            {
                writer.WritePropertyName(LogMessageProperties.LIBRARY_ID);
                writer.WriteValue(logMessage.LibraryId);
            }

            if (logMessage.TargetGraphs != null &&
                logMessage.TargetGraphs.Any() &&
                logMessage.TargetGraphs.All(l => !string.IsNullOrEmpty(l)))
            {
                writer.WritePropertyName(LogMessageProperties.TARGET_GRAPHS);
                WriteArray(writer, logMessage.TargetGraphs);
            }

            writer.WriteEndObject();
        }

        internal static void WriteLogMessages(JsonWriter writer, IEnumerable<IAssetsLogMessage> logMessages, string projectPath)
        {
            writer.WriteStartArray();

            foreach (var logMessage in logMessages)
            {
                WriteLogMessage(writer, logMessage, projectPath);
            }

            writer.WriteEndArray();
        }

        private static void WriteTargetLibrary(JsonWriter writer, LockFileTargetLibrary library)
        {
            writer.WritePropertyName(library.Name + "/" + library.Version.ToNormalizedString());

            writer.WriteStartObject();

            if (library.Type != null)
            {
                writer.WritePropertyName(TypeProperty);
                writer.WriteValue(library.Type);
            }

            if (library.Framework != null)
            {
                writer.WritePropertyName(FrameworkProperty);
                writer.WriteValue(library.Framework);
            }

            if (library.Dependencies.Count > 0)
            {
                var ordered = library.Dependencies.OrderBy(dependency => dependency.Id, StringComparer.Ordinal);

                writer.WritePropertyName(DependenciesProperty);
                JsonUtility.WriteObject(writer, ordered, JsonUtility.WritePackageDependencyWithLegacyString);
            }

            if (library.FrameworkAssemblies.Count > 0)
            {
                var ordered = library.FrameworkAssemblies.OrderBy(assembly => assembly, StringComparer.Ordinal);

                writer.WritePropertyName(FrameworkAssembliesProperty);
                WriteArray(writer, ordered);
            }

            if (library.CompileTimeAssemblies.Count > 0)
            {
                var ordered = library.CompileTimeAssemblies.OrderBy(assembly => assembly.Path, StringComparer.Ordinal);

                writer.WritePropertyName(CompileProperty);
                JsonUtility.WriteObject(writer, ordered, WriteFileItem);
            }

            if (library.AnalyzerAssets.Count > 0)
            {
                var ordered = library.AnalyzerAssets.OrderBy(assembly => assembly.Path, StringComparer.Ordinal);

                writer.WritePropertyName(AnalyzersProperty);
                JsonUtility.WriteObject(writer, ordered, WriteFileItem);
            }

            if (library.RuntimeAssemblies.Count > 0)
            {
                var ordered = library.RuntimeAssemblies.OrderBy(assembly => assembly.Path, StringComparer.Ordinal);

                writer.WritePropertyName(RuntimeProperty);
                JsonUtility.WriteObject(writer, ordered, WriteFileItem);
            }

            if (library.FrameworkReferences.Count > 0)
            {
                var ordered = library.FrameworkReferences.OrderBy(reference => reference, StringComparer.Ordinal);

                writer.WritePropertyName(FrameworkReferencesProperty);
                WriteArray(writer, ordered);
            }

            if (library.ResourceAssemblies.Count > 0)
            {
                var ordered = library.ResourceAssemblies.OrderBy(assembly => assembly.Path, StringComparer.Ordinal);

                writer.WritePropertyName(ResourceProperty);
                JsonUtility.WriteObject(writer, ordered, WriteFileItem);
            }

            if (library.NativeLibraries.Count > 0)
            {
                var ordered = library.NativeLibraries.OrderBy(assembly => assembly.Path, StringComparer.Ordinal);

                writer.WritePropertyName(NativeProperty);
                JsonUtility.WriteObject(writer, ordered, WriteFileItem);
            }

            if (library.ContentFiles.Count > 0)
            {
                var ordered = library.ContentFiles.OrderBy(assembly => assembly.Path, StringComparer.Ordinal);

                writer.WritePropertyName(ContentFilesProperty);
                JsonUtility.WriteObject(writer, ordered, WriteFileItem);
            }

            if (library.Build.Count > 0)
            {
                var ordered = library.Build.OrderBy(assembly => assembly.Path, StringComparer.Ordinal);

                writer.WritePropertyName(BuildProperty);
                JsonUtility.WriteObject(writer, ordered, WriteFileItem);
            }

            if (library.BuildMultiTargeting.Count > 0)
            {
                var ordered = library.BuildMultiTargeting.OrderBy(assembly => assembly.Path, StringComparer.Ordinal);

                writer.WritePropertyName(BuildMultiTargetingProperty);
                JsonUtility.WriteObject(writer, ordered, WriteFileItem);
            }

            if (library.RuntimeTargets.Count > 0)
            {
                var ordered = library.RuntimeTargets.OrderBy(assembly => assembly.Path, StringComparer.Ordinal);

                writer.WritePropertyName(RuntimeTargetsProperty);
                JsonUtility.WriteObject(writer, ordered, WriteFileItem);
            }

            if (library.ToolsAssemblies.Count > 0)
            {
                var ordered = library.ToolsAssemblies.OrderBy(assembly => assembly.Path, StringComparer.Ordinal);

                writer.WritePropertyName(ToolsProperty);
                JsonUtility.WriteObject(writer, ordered, WriteFileItem);
            }

            if (library.EmbedAssemblies.Count > 0)
            {
                var ordered = library.EmbedAssemblies.OrderBy(assembly => assembly.Path, StringComparer.Ordinal);

                writer.WritePropertyName(EmbedProperty);
                JsonUtility.WriteObject(writer, ordered, WriteFileItem);
            }

            writer.WriteEndObject();
        }

        private static void WriteProjectFileDependencyGroup(JsonWriter writer, ProjectFileDependencyGroup frameworkInfo)
        {
            writer.WritePropertyName(frameworkInfo.FrameworkName);
            WriteArray(writer, frameworkInfo.Dependencies);
        }

        private static void WriteFileItem(JsonWriter writer, LockFileItem item)
        {
            writer.WritePropertyName(item.Path);

            writer.WriteStartObject();

            foreach (var property in item.Properties.OrderBy(x => x.Key, StringComparer.Ordinal))
            {
                writer.WritePropertyName(property.Key);

                if (bool.TrueString.Equals(property.Value, StringComparison.OrdinalIgnoreCase))
                {
                    writer.WriteValue(true);
                }
                else if (bool.FalseString.Equals(property.Value, StringComparison.OrdinalIgnoreCase))
                {
                    writer.WriteValue(false);
                }
                else
                {
                    writer.WriteValue(property.Value);
                }
            }

            writer.WriteEndObject();
        }

        private static void WritePathArray(JsonWriter writer, string property, IEnumerable<string> items)
        {
            using var itemsEnumerator = items.NoAllocEnumerate().GetEnumerator();
            if (itemsEnumerator.MoveNext())
            {
                var orderedItems = items
                    .Select(f => GetPathWithForwardSlashes(f))
                    .OrderBy(f => f, StringComparer.Ordinal);

                writer.WritePropertyName(property);
                WriteArray(writer, orderedItems);
            }
        }

        internal static void WriteArray(JsonWriter writer, IEnumerable<string> values)
        {
            writer.WriteStartArray();
            foreach (var value in values)
            {
                writer.WriteValue(value);
            }
            writer.WriteEndArray();
        }

        private static string GetPathWithForwardSlashes(string path)
        {
            return path.Replace('\\', '/');
        }

        private static void WriteCentralTransitiveDependencyGroup(IObjectWriter writer, IList<CentralTransitiveDependencyGroup> centralTransitiveDependencyGroups)
        {
            writer.WriteObjectStart();

            foreach (var centralTransitiveDepGroup in centralTransitiveDependencyGroups.OrderBy(ptdg => ptdg.FrameworkName))
            {
                PackageSpecWriter.SetCentralTransitveDependencyGroup(writer, centralTransitiveDepGroup.FrameworkName, centralTransitiveDepGroup.TransitiveDependencies);
            }

            writer.WriteObjectEnd();
        }

    }
}

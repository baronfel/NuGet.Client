// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#nullable disable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using NuGet.Common;
using NuGet.Packaging.Core;

namespace NuGet.ProjectModel
{
    public partial class LockFileFormat
    {
        private static void WriteToStream(Stream stream, LockFile lockFile)
        {
            using (var writer = new Utf8JsonWriter(stream, NewtonsoftJsonCompatibility.WriterOptions))
            {
                WriteLockFile(writer, lockFile);
            }
        }

        private static void WriteLockFile(Utf8JsonWriter writer, LockFile lockFile)
        {
            var objectWriter = new Utf8JsonObjectWriter(writer);

            writer.WriteStartObject();
            writer.WriteNumber(VersionProperty, lockFile.Version);

            writer.WritePropertyName(TargetsProperty);
            WriteObject(writer, lockFile.Targets, WriteTarget);

            writer.WritePropertyName(LibrariesProperty);
            WriteObject(writer, lockFile.Libraries, WriteLibrary);

            writer.WritePropertyName(ProjectFileDependencyGroupsProperty);
            WriteObject(writer, lockFile.ProjectFileDependencyGroups, WriteProjectFileDependencyGroup);

            if (lockFile.PackageFolders?.Any() == true)
            {
                writer.WritePropertyName(PackageFoldersProperty);
                WriteObject(writer, lockFile.PackageFolders, WriteFileItem);
            }

            if (lockFile.Version >= 2 && lockFile.PackageSpec != null)
            {
                writer.WritePropertyName(PackageSpecProperty);
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
                writer.WritePropertyName(LogsProperty);
                WriteLogMessages(writer, lockFile.LogMessages, projectPath);
            }

            if (lockFile.CentralTransitiveDependencyGroups.Any())
            {
                writer.WritePropertyName(CentralTransitiveDependencyGroupsProperty);
                WriteCentralTransitiveDependencyGroup(objectWriter, lockFile.CentralTransitiveDependencyGroups);
            }

            writer.WriteEndObject();
        }

        private static void WriteLibrary(Utf8JsonWriter writer, LockFileLibrary library)
        {
            writer.WritePropertyName(library.Name + "/" + library.Version.ToNormalizedString());
            writer.WriteStartObject();

            if (library.IsServiceable)
            {
                writer.WriteBoolean(ServicableProperty, library.IsServiceable);
            }

            if (library.Sha512 != null)
            {
                writer.WriteString(Sha512Property, library.Sha512);
            }

            writer.WriteString(TypeProperty, library.Type);

            if (library.Path != null)
            {
                writer.WriteString(PathProperty, library.Path);
            }

            if (library.MSBuildProject != null)
            {
                writer.WriteString(MSBuildProjectProperty, library.MSBuildProject);
            }

            if (library.HasTools)
            {
                writer.WriteBoolean(HasToolsProperty, library.HasTools);
            }

            WritePathArray(writer, FilesProperty, library.Files);
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
            writer.WriteString(LogMessageProperties.CODE, Enum.GetName(typeof(NuGetLogCode), logMessage.Code));
            writer.WriteString(LogMessageProperties.LEVEL, Enum.GetName(typeof(LogLevel), logMessage.Level));

            if (logMessage.Level == LogLevel.Warning)
            {
                writer.WriteNumber(LogMessageProperties.WARNING_LEVEL, (int)logMessage.WarningLevel);
            }

            if (logMessage.FilePath != null &&
                (projectPath == null || !PathUtility.GetStringComparerBasedOnOS().Equals(logMessage.FilePath, projectPath)))
            {
                writer.WriteString(LogMessageProperties.FILE_PATH, logMessage.FilePath);
            }

            if (logMessage.StartLineNumber > 0)
            {
                writer.WriteNumber(LogMessageProperties.START_LINE_NUMBER, logMessage.StartLineNumber);
            }

            if (logMessage.StartColumnNumber > 0)
            {
                writer.WriteNumber(LogMessageProperties.START_COLUMN_NUMBER, logMessage.StartColumnNumber);
            }

            if (logMessage.EndLineNumber > 0)
            {
                writer.WriteNumber(LogMessageProperties.END_LINE_NUMBER, logMessage.EndLineNumber);
            }

            if (logMessage.EndColumnNumber > 0)
            {
                writer.WriteNumber(LogMessageProperties.END_COLUMN_NUMBER, logMessage.EndColumnNumber);
            }

            if (logMessage.Message != null)
            {
                writer.WriteString(LogMessageProperties.MESSAGE, logMessage.Message);
            }

            if (logMessage.LibraryId != null)
            {
                writer.WriteString(LogMessageProperties.LIBRARY_ID, logMessage.LibraryId);
            }

            if (logMessage.TargetGraphs != null &&
                logMessage.TargetGraphs.Any() &&
                logMessage.TargetGraphs.All(targetGraph => !string.IsNullOrEmpty(targetGraph)))
            {
                writer.WritePropertyName(LogMessageProperties.TARGET_GRAPHS);
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
            writer.WritePropertyName(library.Name + "/" + library.Version.ToNormalizedString());
            writer.WriteStartObject();

            if (library.Type != null)
            {
                writer.WriteString(TypeProperty, library.Type);
            }

            if (library.Framework != null)
            {
                writer.WriteString(FrameworkProperty, library.Framework);
            }

            if (library.Dependencies.Count > 0)
            {
                IEnumerable<PackageDependency> ordered = library.Dependencies.OrderBy(
                    dependency => dependency.Id,
                    StringComparer.Ordinal);

                writer.WritePropertyName(DependenciesProperty);
                WriteObject(writer, ordered, WritePackageDependencyWithLegacyString);
            }

            if (library.FrameworkAssemblies.Count > 0)
            {
                IEnumerable<string> ordered = library.FrameworkAssemblies.OrderBy(
                    assembly => assembly,
                    StringComparer.Ordinal);

                writer.WritePropertyName(FrameworkAssembliesProperty);
                WriteArray(writer, ordered);
            }

            WriteItems(writer, CompileProperty, library.CompileTimeAssemblies);
            WriteItems(writer, AnalyzersProperty, library.AnalyzerAssets);
            WriteItems(writer, RuntimeProperty, library.RuntimeAssemblies);

            if (library.FrameworkReferences.Count > 0)
            {
                IEnumerable<string> ordered = library.FrameworkReferences.OrderBy(
                    reference => reference,
                    StringComparer.Ordinal);

                writer.WritePropertyName(FrameworkReferencesProperty);
                WriteArray(writer, ordered);
            }

            WriteItems(writer, ResourceProperty, library.ResourceAssemblies);
            WriteItems(writer, NativeProperty, library.NativeLibraries);
            WriteItems(writer, ContentFilesProperty, library.ContentFiles);
            WriteItems(writer, BuildProperty, library.Build);
            WriteItems(writer, BuildMultiTargetingProperty, library.BuildMultiTargeting);
            WriteItems(writer, RuntimeTargetsProperty, library.RuntimeTargets);
            WriteItems(writer, ToolsProperty, library.ToolsAssemblies);
            WriteItems(writer, EmbedProperty, library.EmbedAssemblies);

            writer.WriteEndObject();
        }

        private static void WriteItems<T>(Utf8JsonWriter writer, string propertyName, IList<T> items)
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

        private static void WritePathArray(Utf8JsonWriter writer, string property, IEnumerable<string> items)
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

    }
}

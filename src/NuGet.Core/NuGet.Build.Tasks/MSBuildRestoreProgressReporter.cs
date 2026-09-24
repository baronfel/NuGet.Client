// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#nullable disable

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Threading;
using Microsoft.Build.Framework;
using NuGet.Commands;

namespace NuGet.Build.Tasks
{
    internal sealed class MSBuildRestoreProgressReporter : IRestoreOperationProgressReporter, IDisposable
    {
        private readonly ITaskProgressReporter _reporter;
        private int _completedProjects;
        private int _totalProjects;

        internal MSBuildRestoreProgressReporter(IBuildEngine buildEngine)
        {
            _reporter = (buildEngine as IBuildEngine10)?.EngineServices.CreateTaskProgressReporter(
                Strings.ResourceManager.GetString("RestoreProgressTitle", Strings.Culture),
                TaskProgressUnit.Items);
        }

        public void Start(int totalProjects)
        {
            _totalProjects = totalProjects;
            _reporter?.Report(new TaskProgressUpdate(
                0,
                totalProjects,
                Strings.ResourceManager.GetString("RestoreProgressResolving", Strings.Culture)));
        }

        public void StartProject(string projectPath)
        {
            Report(
                Volatile.Read(ref _completedProjects),
                "RestoreProgressRestoring",
                projectPath);
        }

        public void CompleteProject(string projectPath)
        {
            Report(
                Interlocked.Increment(ref _completedProjects),
                "RestoreProgressStatus",
                projectPath);
        }

        public void ReportPackageDownload(string packageId, string packageVersion)
        {
            string status = string.Format(
                CultureInfo.CurrentCulture,
                Strings.ResourceManager.GetString("RestoreProgressDownloading", Strings.Culture),
                packageId,
                packageVersion);

            _reporter?.Report(new TaskProgressUpdate(Volatile.Read(ref _completedProjects), _totalProjects, status));
        }

        public void StartProjectUpdate(string projectPath, IReadOnlyList<string> updatedFiles)
        {
        }

        public void EndProjectUpdate(string projectPath, IReadOnlyList<string> updatedFiles)
        {
        }

        private void Report(int completed, string resourceName, string projectPath)
        {
            string status = string.Format(
                CultureInfo.CurrentCulture,
                Strings.ResourceManager.GetString(resourceName, Strings.Culture),
                Path.GetFileName(projectPath));

            _reporter?.Report(new TaskProgressUpdate(completed, _totalProjects, status));
        }

        internal void Complete() => _reporter?.Complete();

        internal void Cancel() => _reporter?.Cancel(Strings.RestoreCanceled);

        internal void Fail() => _reporter?.Fail();

        public void Dispose() => _reporter?.Dispose();
    }
}

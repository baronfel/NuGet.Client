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
    internal sealed class MSBuildRestoreProgressReporter : IRestoreProgressReporter, IDisposable
    {
        private readonly ITaskProgressReporter _reporter;
        private readonly int _totalProjects;
        private int _completedProjects;

        internal MSBuildRestoreProgressReporter(IBuildEngine buildEngine, int totalProjects)
        {
            _totalProjects = totalProjects;
            _reporter = (buildEngine as IBuildEngine10)?.EngineServices.CreateTaskProgressReporter(
                Strings.ResourceManager.GetString("RestoreProgressTitle", Strings.Culture),
                TaskProgressUnit.Items);
            _reporter?.Report(new TaskProgressUpdate(0, totalProjects));
        }

        public void StartProjectUpdate(string projectPath, IReadOnlyList<string> updatedFiles)
        {
        }

        public void EndProjectUpdate(string projectPath, IReadOnlyList<string> updatedFiles)
        {
            int completed = Interlocked.Increment(ref _completedProjects);
            string status = string.Format(
                CultureInfo.CurrentCulture,
                Strings.ResourceManager.GetString("RestoreProgressStatus", Strings.Culture),
                Path.GetFileName(projectPath));

            _reporter?.Report(new TaskProgressUpdate(completed, _totalProjects, status));
        }

        internal void Complete() => _reporter?.Complete();

        internal void Cancel() => _reporter?.Cancel(Strings.RestoreCanceled);

        internal void Fail() => _reporter?.Fail();

        public void Dispose() => _reporter?.Dispose();
    }
}

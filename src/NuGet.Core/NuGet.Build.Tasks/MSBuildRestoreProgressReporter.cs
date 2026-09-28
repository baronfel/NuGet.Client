// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Threading;
using Microsoft.Build.Framework;
using NuGet.Commands;

namespace NuGet.Build.Tasks
{
    internal sealed class MSBuildRestoreProgressReporter : IRestoreOperationProgressReporter, IDisposable
    {
        private static readonly long MinimumStatusUpdateInterval = Stopwatch.Frequency / 4;

        private readonly object _overallLock = new();
        private readonly object _packageLock = new();
        private readonly IBuildEngine10? _buildEngine;
        private readonly ITaskProgressReporter? _overallReporter;
        private ITaskProgressReporter? _packageReporter;
        private int _completedProjects;
        private int _totalProjects;
        private int _projectsResolving;
        private int _projectsInstalling;
        private int _projectsCommitting;
        private int _projectsUpToDate;
        private int _projectsRemainingResolution;
        private long _packagesTotal;
        private long _packagesCompleted;
        private long _lastOverallStatusUpdate;
        private long _lastPackageStatusUpdate;
        private int _lastReportedProjectsCompleted;
        private long _lastReportedPackagesCompleted;
        private bool _packageOperationFinished;
        private bool _overallOutcomeSet;
        private string _packageStatus = string.Empty;
        private string? _lastCompletedProject;

        internal MSBuildRestoreProgressReporter(IBuildEngine? buildEngine)
        {
            _buildEngine = buildEngine as IBuildEngine10;
            _overallReporter = _buildEngine?.EngineServices.CreateTaskProgressReporter(
                GetResourceString("RestoreProgressTitle"),
                TaskProgressUnit.Items);

            _overallReporter?.Report(new TaskProgressUpdate(
                0,
                null,
                GetResourceString("RestoreProgressPreparing")));
        }

        public void Start(int totalProjects)
        {
            Interlocked.Exchange(ref _totalProjects, totalProjects);
            Interlocked.Exchange(ref _projectsResolving, totalProjects);
            Interlocked.Exchange(ref _projectsRemainingResolution, totalProjects);
            ReportOverallProgress(force: true);
        }

        public void StartProject(string projectPath)
        {
            ReportOverallProgress(force: false);
        }

        public void StartPackageInstallBatch(int packageCount)
        {
            if (packageCount <= 0)
            {
                return;
            }

            Interlocked.Decrement(ref _projectsResolving);
            Interlocked.Increment(ref _projectsInstalling);
            ReportOverallProgress(force: false);

            lock (_packageLock)
            {
                Interlocked.Add(ref _packagesTotal, packageCount);

                if (_packageOperationFinished)
                {
                    return;
                }

                bool isFirstBatch = _packageReporter is null;
                if (isFirstBatch)
                {
                    _packageReporter = _buildEngine?.EngineServices.CreateTaskProgressReporter(
                        GetResourceString("RestoreProgressPackagesTitle"),
                        TaskProgressUnit.Items);
                    _packageStatus = GetResourceString("RestoreProgressPackagesTitle");
                }

                ReportPackageProgress(force: isFirstBatch);
            }
        }

        public void ReportPackageInstall(string packageId, string packageVersion)
        {
            lock (_packageLock)
            {
                _packageStatus = string.Format(
                    CultureInfo.CurrentCulture,
                    GetResourceString("RestoreProgressInstallingPackage"),
                    packageId,
                    packageVersion);
            }

            ReportPackageProgress(force: false);
        }

        public void CompletePackageInstall()
        {
            Interlocked.Increment(ref _packagesCompleted);

            lock (_packageLock)
            {
                _packageStatus = GetPackageProgressStatus();
            }

            ReportPackageProgress(force: false);
            TryCompletePackageOperation();
        }

        public void EndPackageInstallBatch()
        {
            Interlocked.Decrement(ref _projectsInstalling);
            Interlocked.Increment(ref _projectsResolving);

            if (Volatile.Read(ref _packagesCompleted) >= Volatile.Read(ref _packagesTotal) &&
                Volatile.Read(ref _projectsRemainingResolution) > 0)
            {
                lock (_packageLock)
                {
                    _packageStatus = GetResourceString("RestoreProgressWaitingForDependencies");
                }

                ReportPackageProgress(force: false);
            }

            ReportOverallProgress(force: false);
            TryCompletePackageOperation();
        }

        public void StartProjectCommit(bool isNoOp)
        {
            Interlocked.Decrement(ref _projectsResolving);
            Interlocked.Decrement(ref _projectsRemainingResolution);

            if (isNoOp)
            {
                Interlocked.Increment(ref _projectsUpToDate);
            }
            else
            {
                Interlocked.Increment(ref _projectsCommitting);
            }

            ReportOverallProgress(force: false);
            TryCompletePackageOperation();
        }

        public void CompleteProject(string projectPath, bool commitStarted, bool commitSucceeded, bool isNoOp)
        {
            if (!commitStarted)
            {
                Interlocked.Decrement(ref _projectsResolving);
                Interlocked.Decrement(ref _projectsRemainingResolution);
            }
            else if (!isNoOp)
            {
                Interlocked.Decrement(ref _projectsCommitting);
            }

            if (commitSucceeded)
            {
                Interlocked.Increment(ref _completedProjects);
                Volatile.Write(ref _lastCompletedProject, Path.GetFileName(projectPath));
            }

            ReportOverallProgress(force: false);
            TryCompletePackageOperation();
        }

        public void StartProjectUpdate(string projectPath, IReadOnlyList<string> updatedFiles)
        {
        }

        public void EndProjectUpdate(string projectPath, IReadOnlyList<string> updatedFiles)
        {
        }

        internal void Complete()
        {
            CompletePackageOperation();
            SetOverallOutcome(static reporter => reporter.Complete());
        }

        internal void Cancel()
        {
            CancelPackageOperation();
            SetOverallOutcome(reporter => reporter.Cancel(Strings.RestoreCanceled));
        }

        internal void Fail()
        {
            FailPackageOperation();
            SetOverallOutcome(static reporter => reporter.Fail());
        }

        public void Dispose()
        {
            lock (_packageLock)
            {
                _packageReporter?.Dispose();
                _packageReporter = null;
            }

            lock (_overallLock)
            {
                _overallReporter?.Dispose();
            }
        }

        private void TryCompletePackageOperation()
        {
            if (Volatile.Read(ref _projectsRemainingResolution) == 0 &&
                Volatile.Read(ref _packagesCompleted) >= Volatile.Read(ref _packagesTotal))
            {
                CompletePackageOperation();
            }
        }

        private void CompletePackageOperation()
        {
            lock (_packageLock)
            {
                if (_packageReporter is null || _packageOperationFinished)
                {
                    return;
                }

                _packageStatus = GetPackageProgressStatus();
                ReportPackageProgress(force: true);
                ITaskProgressReporter reporter = _packageReporter;
                _packageReporter = null;
                _packageOperationFinished = true;
                reporter.Complete();
                reporter.Dispose();
            }
        }

        private void CancelPackageOperation()
        {
            FinishPackageOperation(static reporter => reporter.Cancel(Strings.RestoreCanceled));
        }

        private void FailPackageOperation()
        {
            FinishPackageOperation(static reporter => reporter.Fail());
        }

        private void FinishPackageOperation(Action<ITaskProgressReporter> finish)
        {
            lock (_packageLock)
            {
                if (_packageReporter is null || _packageOperationFinished)
                {
                    return;
                }

                ITaskProgressReporter reporter = _packageReporter;
                _packageReporter = null;
                _packageOperationFinished = true;
                finish(reporter);
                reporter.Dispose();
            }
        }

        private void ReportOverallProgress(bool force)
        {
            lock (_overallLock)
            {
                if (_overallReporter is null || _overallOutcomeSet)
                {
                    return;
                }

                long now = Stopwatch.GetTimestamp();
                if (!force &&
                    _lastOverallStatusUpdate != 0 &&
                    now - _lastOverallStatusUpdate < MinimumStatusUpdateInterval)
                {
                    return;
                }

                int completed = Math.Max(
                    _lastReportedProjectsCompleted,
                    Volatile.Read(ref _completedProjects));
                int total = Volatile.Read(ref _totalProjects);

                _overallReporter.Report(new TaskProgressUpdate(completed, total, GetOverallStatus()));
                _lastReportedProjectsCompleted = completed;
                _lastOverallStatusUpdate = now;
            }
        }

        private void ReportPackageProgress(bool force)
        {
            lock (_packageLock)
            {
                if (_packageReporter is null || _packageOperationFinished)
                {
                    return;
                }

                long now = Stopwatch.GetTimestamp();
                if (!force &&
                    _lastPackageStatusUpdate != 0 &&
                    now - _lastPackageStatusUpdate < MinimumStatusUpdateInterval)
                {
                    return;
                }

                long completed = Math.Max(
                    _lastReportedPackagesCompleted,
                    Volatile.Read(ref _packagesCompleted));
                long total = Volatile.Read(ref _packagesTotal);

                _packageReporter.Report(new TaskProgressUpdate(completed, total, _packageStatus));
                _lastReportedPackagesCompleted = completed;
                _lastPackageStatusUpdate = now;
            }
        }

        private void SetOverallOutcome(Action<ITaskProgressReporter> finish)
        {
            lock (_overallLock)
            {
                if (_overallReporter is null || _overallOutcomeSet)
                {
                    return;
                }

                ReportOverallProgress(force: true);
                _overallOutcomeSet = true;
                finish(_overallReporter);
            }
        }

        private string GetOverallStatus()
        {
            var phases = new List<string>(4);
            AddPhaseStatus(phases, "RestoreProgressPhaseResolving", Volatile.Read(ref _projectsResolving));
            AddPhaseStatus(phases, "RestoreProgressPhaseInstalling", Volatile.Read(ref _projectsInstalling));
            AddPhaseStatus(phases, "RestoreProgressPhaseCommitting", Volatile.Read(ref _projectsCommitting));
            AddPhaseStatus(phases, "RestoreProgressPhaseUpToDate", Volatile.Read(ref _projectsUpToDate));

            if (phases.Count > 0)
            {
                return string.Join(", ", phases);
            }

            string? lastCompletedProject = Volatile.Read(ref _lastCompletedProject);
            return lastCompletedProject is null
                ? GetResourceString("RestoreProgressPreparing")
                : string.Format(
                    CultureInfo.CurrentCulture,
                    GetResourceString("RestoreProgressStatus"),
                    lastCompletedProject);
        }

        private string GetPackageProgressStatus()
        {
            return string.Format(
                CultureInfo.CurrentCulture,
                GetResourceString("RestoreProgressPackagesStatus"),
                Volatile.Read(ref _packagesCompleted),
                Volatile.Read(ref _packagesTotal));
        }

        private static void AddPhaseStatus(List<string> phases, string resourceName, int count)
        {
            if (count > 0)
            {
                phases.Add(string.Format(CultureInfo.CurrentCulture, GetResourceString(resourceName), count));
            }
        }

        private static string GetResourceString(string name)
        {
            return Strings.ResourceManager.GetString(name, Strings.Culture)
                ?? throw new InvalidOperationException($"The resource '{name}' was not found.");
        }
    }
}

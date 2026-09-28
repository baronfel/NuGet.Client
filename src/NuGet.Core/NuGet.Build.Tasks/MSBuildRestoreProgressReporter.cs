// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.ExceptionServices;
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
        private static readonly TimeSpan ProgressHeartbeatInterval = TimeSpan.FromMilliseconds(250);

        private readonly object _overallLock = new();
        private readonly object _packageLock = new();
        private readonly IBuildEngine10? _buildEngine;
        private readonly ITaskProgressReporter? _overallReporter;
        private readonly ConcurrentDictionary<PackageProgressIdentity, PackageProgressState> _packageProgress = new();
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
        private int _lastReportedProjectsTotal;
        private long _lastReportedPackagesCompleted;
        private long _lastReportedPackagesTotal;
        private bool _packageOperationFinished;
        private bool _overallOutcomeSet;
        private string _packageStatus = string.Empty;
        private string? _lastCompletedProject;
        private ExceptionDispatchInfo? _heartbeatException;
        private Timer? _overallHeartbeatTimer;
        private Timer? _packageHeartbeatTimer;

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
            if (_overallReporter is not null)
            {
                _overallHeartbeatTimer = new Timer(
                    ReportOverallHeartbeat,
                    null,
                    ProgressHeartbeatInterval,
                    ProgressHeartbeatInterval);
            }
        }

        public void Start(int totalProjects)
        {
            ThrowIfHeartbeatFailed();
            Interlocked.Exchange(ref _totalProjects, totalProjects);
            Interlocked.Exchange(ref _projectsResolving, totalProjects);
            Interlocked.Exchange(ref _projectsRemainingResolution, totalProjects);
            ReportOverallProgress(force: true);
        }

        public void StartProject(string projectPath)
        {
            ThrowIfHeartbeatFailed();
            ReportOverallProgress(force: false);
        }

        public void StartPackageInstallBatch(int packageCount)
        {
            ThrowIfHeartbeatFailed();
            if (packageCount <= 0)
            {
                return;
            }

            Interlocked.Decrement(ref _projectsResolving);
            Interlocked.Increment(ref _projectsInstalling);
            ReportOverallProgress(force: false);

            lock (_packageLock)
            {
                if (_packageOperationFinished)
                {
                    return;
                }

                ReportPackageProgress(force: false);
            }
        }

        public bool TryStartPackageInstall(string packageId, string packageVersion)
        {
            ThrowIfHeartbeatFailed();
            if (_buildEngine is null)
            {
                return false;
            }

            var identity = new PackageProgressIdentity(packageId, packageVersion);
            if (!_packageProgress.TryAdd(identity, PackageProgressState.Started))
            {
                return false;
            }

            Interlocked.Increment(ref _packagesTotal);
            lock (_packageLock)
            {
                if (_packageOperationFinished)
                {
                    throw new InvalidOperationException("A package candidate was discovered after package progress completed.");
                }

                _packageReporter ??= _buildEngine.EngineServices.CreateTaskProgressReporter(
                    GetResourceString("RestoreProgressPackagesTitle"),
                    TaskProgressUnit.Items);
                _packageStatus = string.Format(
                    CultureInfo.CurrentCulture,
                    GetResourceString("RestoreProgressInstallingPackage"),
                    packageId,
                    packageVersion);
                if (_packageHeartbeatTimer is null && _packageReporter is not null)
                {
                    _packageHeartbeatTimer = new Timer(
                        ReportPackageHeartbeat,
                        null,
                        ProgressHeartbeatInterval,
                        ProgressHeartbeatInterval);
                }
            }

            ReportPackageProgress(force: true);
            return true;
        }

        public void CompletePackageInstall(string packageId, string packageVersion)
        {
            ThrowIfHeartbeatFailed();
            var identity = new PackageProgressIdentity(packageId, packageVersion);
            if (!_packageProgress.TryUpdate(identity, PackageProgressState.Completed, PackageProgressState.Started))
            {
                throw new InvalidOperationException("A package candidate was completed without a unique start notification.");
            }

            Interlocked.Increment(ref _packagesCompleted);

            lock (_packageLock)
            {
                _packageStatus = GetPackageProgressStatus();
            }

            ReportPackageProgress(force: false);
            ReportOverallProgress(force: false);
            TryCompletePackageOperation();
        }

        public void EndPackageInstallBatch()
        {
            ThrowIfHeartbeatFailed();
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
            ThrowIfHeartbeatFailed();
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
            ThrowIfHeartbeatFailed();
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
            ThrowIfHeartbeatFailed();
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
                _packageHeartbeatTimer?.Dispose();
                _packageHeartbeatTimer = null;
                _packageReporter?.Dispose();
                _packageReporter = null;
            }

            lock (_overallLock)
            {
                _overallHeartbeatTimer?.Dispose();
                _overallHeartbeatTimer = null;
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
                _packageHeartbeatTimer?.Dispose();
                _packageHeartbeatTimer = null;
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

                _packageHeartbeatTimer?.Dispose();
                _packageHeartbeatTimer = null;
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
                int completed = Math.Max(
                    _lastReportedProjectsCompleted,
                    Volatile.Read(ref _completedProjects));
                int totalProjects = Volatile.Read(ref _totalProjects);
                long? total = totalProjects > 0 ? totalProjects : null;
                int reportedTotal = totalProjects > 0 ? totalProjects : 0;
                bool progressChanged = completed != _lastReportedProjectsCompleted ||
                    reportedTotal != _lastReportedProjectsTotal;
                if (!force &&
                    !progressChanged &&
                    _lastOverallStatusUpdate != 0 &&
                    now - _lastOverallStatusUpdate < MinimumStatusUpdateInterval)
                {
                    return;
                }

                _overallReporter.Report(new TaskProgressUpdate(completed, total, GetOverallStatus()));
                _lastReportedProjectsCompleted = completed;
                _lastReportedProjectsTotal = reportedTotal;
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
                long completed = Math.Max(
                    _lastReportedPackagesCompleted,
                    Volatile.Read(ref _packagesCompleted));
                long total = Volatile.Read(ref _packagesTotal);
                bool progressChanged = completed != _lastReportedPackagesCompleted ||
                    total != _lastReportedPackagesTotal;
                if (!force &&
                    !progressChanged &&
                    _lastPackageStatusUpdate != 0 &&
                    now - _lastPackageStatusUpdate < MinimumStatusUpdateInterval)
                {
                    return;
                }

                _packageReporter.Report(new TaskProgressUpdate(completed, total, _packageStatus));
                _lastReportedPackagesCompleted = completed;
                _lastReportedPackagesTotal = total;
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
                _overallHeartbeatTimer?.Dispose();
                _overallHeartbeatTimer = null;
                _overallOutcomeSet = true;
                finish(_overallReporter);
            }
        }

        [SuppressMessage(
            "Design",
            "CA1031:DoNotCatchGeneralExceptionTypes",
            Justification = "Timer callback failures are retained and rethrown on the restore task thread.")]
        private void ReportOverallHeartbeat(object? state)
        {
            try
            {
                ReportOverallProgress(force: true);
            }
            catch (Exception exception)
            {
                Interlocked.CompareExchange(
                    ref _heartbeatException,
                    ExceptionDispatchInfo.Capture(exception),
                    null);
            }
        }

        [SuppressMessage(
            "Design",
            "CA1031:DoNotCatchGeneralExceptionTypes",
            Justification = "Timer callback failures are retained and rethrown on the restore task thread.")]
        private void ReportPackageHeartbeat(object? state)
        {
            try
            {
                ReportPackageProgress(force: true);
            }
            catch (Exception exception)
            {
                Interlocked.CompareExchange(
                    ref _heartbeatException,
                    ExceptionDispatchInfo.Capture(exception),
                    null);
            }
        }

        private void ThrowIfHeartbeatFailed()
        {
            Volatile.Read(ref _heartbeatException)?.Throw();
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

        private readonly struct PackageProgressIdentity : IEquatable<PackageProgressIdentity>
        {
            internal PackageProgressIdentity(string packageId, string packageVersion)
            {
                PackageId = packageId;
                PackageVersion = packageVersion;
            }

            private string PackageId { get; }

            private string PackageVersion { get; }

            public bool Equals(PackageProgressIdentity other)
            {
                return StringComparer.OrdinalIgnoreCase.Equals(PackageId, other.PackageId) &&
                    StringComparer.Ordinal.Equals(PackageVersion, other.PackageVersion);
            }

            public override bool Equals(object? obj)
            {
                return obj is PackageProgressIdentity other && Equals(other);
            }

            public override int GetHashCode()
            {
                unchecked
                {
                    return (StringComparer.OrdinalIgnoreCase.GetHashCode(PackageId) * 397) ^
                        StringComparer.Ordinal.GetHashCode(PackageVersion);
                }
            }
        }

        private enum PackageProgressState
        {
            Started,
            Completed
        }
    }
}

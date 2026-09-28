// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Threading;
using Microsoft.Build.Framework;
using NuGet.Commands;

namespace NuGet.Build.Tasks
{
    [SuppressMessage(
        "Design",
        "CA1031:DoNotCatchGeneralExceptionTypes",
        Justification = "Progress reporting must never fail a restore. Failures stop the affected progress operation and are logged.")]
    internal sealed class MSBuildRestoreProgressReporter : IRestoreOperationProgressReporter, IDisposable
    {
        // MSBuild forwards at most one update per operation every 150ms and drops the rest without a trailing flush.
        // Reporting no more often than this keeps every reported frame visible; the heartbeat flushes pending changes.
        private static readonly long MinimumReportInterval = Stopwatch.Frequency / 5;
        private static readonly TimeSpan ProgressHeartbeatInterval = TimeSpan.FromMilliseconds(100);

        private readonly object _overallLock = new();
        private readonly object _packageLock = new();
        private readonly IBuildEngine10? _buildEngine;
        private readonly Common.ILogger? _log;
        private readonly ConcurrentDictionary<PackageProgressIdentity, PackageProgressState> _packageProgress = new();
        private readonly ConcurrentDictionary<PackageProgressIdentity, InFlightPackage> _inFlightPackages = new();
        private ITaskProgressReporter? _overallReporter;
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
        private string? _lastReportedOverallStatus;
        private long _lastReportedPackagesCompleted;
        private long _lastReportedPackagesTotal;
        private string? _lastReportedPackageStatus;
        private bool _packageOperationFinished;
        private bool _overallOutcomeSet;
        private string _packageStatus = string.Empty;
        private string? _lastCompletedProject;
        private Timer? _overallHeartbeatTimer;
        private Timer? _packageHeartbeatTimer;

        internal MSBuildRestoreProgressReporter(IBuildEngine? buildEngine, Common.ILogger? log = null)
        {
            _buildEngine = buildEngine as IBuildEngine10;
            _log = log;

            try
            {
                _overallReporter = _buildEngine?.EngineServices.CreateTaskProgressReporter(
                    GetResourceString("RestoreProgressTitle"),
                    TaskProgressUnit.Items);
                if (_overallReporter is null)
                {
                    return;
                }

                string status = GetResourceString("RestoreProgressPreparing");
                _overallReporter.Report(new TaskProgressUpdate(0, null, status));
                _lastReportedOverallStatus = status;
                _lastOverallStatusUpdate = Stopwatch.GetTimestamp();
                _overallHeartbeatTimer = new Timer(
                    ReportOverallHeartbeat,
                    null,
                    ProgressHeartbeatInterval,
                    ProgressHeartbeatInterval);
            }
            catch (Exception exception)
            {
                StopOverallOperation(exception.ToString());
            }
        }

        public void Start(int totalProjects)
        {
            Interlocked.Exchange(ref _totalProjects, totalProjects);
            Interlocked.Exchange(ref _projectsResolving, totalProjects);
            Interlocked.Exchange(ref _projectsRemainingResolution, totalProjects);
            ReportOverallProgress(final: false);
        }

        public void StartProject(string projectPath)
        {
            ReportOverallProgress(final: false);
        }

        public void StartPackageInstallBatch(int packageCount)
        {
            if (packageCount <= 0)
            {
                return;
            }

            Interlocked.Decrement(ref _projectsResolving);
            Interlocked.Increment(ref _projectsInstalling);
            ReportOverallProgress(final: false);
            ReportPackageProgress(final: false);
        }

        public bool TryStartPackageInstall(string packageId, string packageVersion)
        {
            if (_buildEngine is null || Volatile.Read(ref _packageOperationFinished))
            {
                return false;
            }

            var identity = new PackageProgressIdentity(packageId, packageVersion);
            if (!_packageProgress.TryAdd(identity, PackageProgressState.Started))
            {
                return false;
            }

            _inFlightPackages.TryAdd(identity, new InFlightPackage(packageId, packageVersion, Stopwatch.GetTimestamp()));

            Interlocked.Increment(ref _packagesTotal);
            lock (_packageLock)
            {
                if (_packageOperationFinished)
                {
                    LogReportingStopped(
                        "RestoreProgressPackagesTitle",
                        FormatResourceString("RestoreProgressPackageAfterCompletion", packageId, packageVersion));
                    return false;
                }

                try
                {
                    _packageReporter ??= _buildEngine.EngineServices.CreateTaskProgressReporter(
                        GetResourceString("RestoreProgressPackagesTitle"),
                        TaskProgressUnit.Items);
                    _packageStatus = GetPackageProgressStatus();
                    if (_packageHeartbeatTimer is null && _packageReporter is not null)
                    {
                        _packageHeartbeatTimer = new Timer(
                            ReportPackageHeartbeat,
                            null,
                            ProgressHeartbeatInterval,
                            ProgressHeartbeatInterval);
                    }
                }
                catch (Exception exception)
                {
                    StopPackageOperation(exception.ToString());
                    return false;
                }
            }

            ReportPackageProgress(final: false);
            return true;
        }

        public void CompletePackageInstall(string packageId, string packageVersion)
        {
            var identity = new PackageProgressIdentity(packageId, packageVersion);
            if (!_packageProgress.TryUpdate(identity, PackageProgressState.Completed, PackageProgressState.Started))
            {
                StopPackageOperation(FormatResourceString("RestoreProgressPackageMismatch", packageId, packageVersion));
                return;
            }

            _inFlightPackages.TryRemove(identity, out _);

            Interlocked.Increment(ref _packagesCompleted);

            lock (_packageLock)
            {
                if (_packageOperationFinished)
                {
                    return;
                }

                try
                {
                    _packageStatus = GetPackageProgressStatus();
                }
                catch (Exception exception)
                {
                    StopPackageOperation(exception.ToString());
                    return;
                }
            }

            ReportPackageProgress(final: false);
            ReportOverallProgress(final: false);
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
                    if (!_packageOperationFinished)
                    {
                        try
                        {
                            _packageStatus = GetResourceString("RestoreProgressWaitingForDependencies");
                        }
                        catch (Exception exception)
                        {
                            StopPackageOperation(exception.ToString());
                        }
                    }
                }

                ReportPackageProgress(final: false);
            }

            ReportOverallProgress(final: false);
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

            ReportOverallProgress(final: false);
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

            ReportOverallProgress(final: false);
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
            FinishPackageOperation(static reporter => reporter.Cancel(Strings.RestoreCanceled));
            SetOverallOutcome(static reporter => reporter.Cancel(Strings.RestoreCanceled));
        }

        internal void Fail()
        {
            FinishPackageOperation(static reporter => reporter.Fail());
            SetOverallOutcome(static reporter => reporter.Fail());
        }

        public void Dispose()
        {
            Timer? packageTimer;
            ITaskProgressReporter? packageReporter;
            lock (_packageLock)
            {
                packageTimer = _packageHeartbeatTimer;
                _packageHeartbeatTimer = null;
                packageReporter = _packageReporter;
                _packageReporter = null;
                _packageOperationFinished = true;
            }

            Timer? overallTimer;
            ITaskProgressReporter? overallReporter;
            lock (_overallLock)
            {
                overallTimer = _overallHeartbeatTimer;
                _overallHeartbeatTimer = null;
                overallReporter = _overallReporter;
                _overallReporter = null;
                _overallOutcomeSet = true;
            }

            packageTimer?.Dispose();
            overallTimer?.Dispose();
            TryDispose(packageReporter);
            TryDispose(overallReporter);
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

                try
                {
                    _packageStatus = GetPackageProgressStatus();
                }
                catch (Exception exception)
                {
                    StopPackageOperation(exception.ToString());
                    return;
                }

                ReportPackageProgress(final: true);
                FinishPackageOperation(static reporter => reporter.Complete());
            }
        }

        private void FinishPackageOperation(Action<ITaskProgressReporter> finish)
        {
            Timer? timer;
            ITaskProgressReporter? reporter;
            lock (_packageLock)
            {
                if (_packageReporter is null || _packageOperationFinished)
                {
                    return;
                }

                timer = _packageHeartbeatTimer;
                _packageHeartbeatTimer = null;
                reporter = _packageReporter;
                _packageReporter = null;
                _packageOperationFinished = true;
            }

            timer?.Dispose();
            try
            {
                finish(reporter);
            }
            catch (Exception exception)
            {
                LogReportingStopped("RestoreProgressPackagesTitle", exception.ToString());
            }
            finally
            {
                TryDispose(reporter);
            }
        }

        private void StopPackageOperation(string reason)
        {
            Timer? timer;
            ITaskProgressReporter? reporter;
            lock (_packageLock)
            {
                if (_packageOperationFinished)
                {
                    return;
                }

                timer = _packageHeartbeatTimer;
                _packageHeartbeatTimer = null;
                reporter = _packageReporter;
                _packageReporter = null;
                _packageOperationFinished = true;
            }

            timer?.Dispose();
            TryDispose(reporter);
            LogReportingStopped("RestoreProgressPackagesTitle", reason);
        }

        private void StopOverallOperation(string reason)
        {
            Timer? timer;
            ITaskProgressReporter? reporter;
            lock (_overallLock)
            {
                if (_overallOutcomeSet)
                {
                    return;
                }

                timer = _overallHeartbeatTimer;
                _overallHeartbeatTimer = null;
                reporter = _overallReporter;
                _overallReporter = null;
                _overallOutcomeSet = true;
            }

            timer?.Dispose();
            TryDispose(reporter);
            LogReportingStopped("RestoreProgressTitle", reason);
        }

        private void ReportOverallProgress(bool final)
        {
            lock (_overallLock)
            {
                if (_overallReporter is null || _overallOutcomeSet)
                {
                    return;
                }

                try
                {
                    int completed = Math.Max(
                        _lastReportedProjectsCompleted,
                        Volatile.Read(ref _completedProjects));
                    int totalProjects = Volatile.Read(ref _totalProjects);
                    long? total = totalProjects > 0 ? totalProjects : null;
                    int reportedTotal = totalProjects > 0 ? totalProjects : 0;
                    string status = GetOverallStatus();
                    bool countsChanged = completed != _lastReportedProjectsCompleted ||
                        reportedTotal != _lastReportedProjectsTotal;
                    if (!countsChanged && string.Equals(status, _lastReportedOverallStatus, StringComparison.Ordinal))
                    {
                        return;
                    }

                    long now = Stopwatch.GetTimestamp();
                    if (!final && now - _lastOverallStatusUpdate < MinimumReportInterval)
                    {
                        // The heartbeat flushes this change after the throttle window.
                        return;
                    }

                    _overallReporter.Report(new TaskProgressUpdate(completed, total, status));
                    _lastReportedProjectsCompleted = completed;
                    _lastReportedProjectsTotal = reportedTotal;
                    _lastReportedOverallStatus = status;
                    _lastOverallStatusUpdate = now;
                }
                catch (Exception exception)
                {
                    StopOverallOperation(exception.ToString());
                }
            }
        }

        private void ReportPackageProgress(bool final)
        {
            lock (_packageLock)
            {
                if (_packageReporter is null || _packageOperationFinished)
                {
                    return;
                }

                try
                {
                    long completed = Math.Max(
                        _lastReportedPackagesCompleted,
                        Volatile.Read(ref _packagesCompleted));
                    long total = Volatile.Read(ref _packagesTotal);
                    string status = _packageStatus;
                    bool countsChanged = completed != _lastReportedPackagesCompleted ||
                        total != _lastReportedPackagesTotal;
                    if (!countsChanged && string.Equals(status, _lastReportedPackageStatus, StringComparison.Ordinal))
                    {
                        return;
                    }

                    long now = Stopwatch.GetTimestamp();
                    if (!final && now - _lastPackageStatusUpdate < MinimumReportInterval)
                    {
                        // The heartbeat flushes this change after the throttle window.
                        return;
                    }

                    _packageReporter.Report(new TaskProgressUpdate(completed, total, status));
                    _lastReportedPackagesCompleted = completed;
                    _lastReportedPackagesTotal = total;
                    _lastReportedPackageStatus = status;
                    _lastPackageStatusUpdate = now;
                }
                catch (Exception exception)
                {
                    StopPackageOperation(exception.ToString());
                }
            }
        }

        private void SetOverallOutcome(Action<ITaskProgressReporter> finish)
        {
            ReportOverallProgress(final: true);

            Timer? timer;
            ITaskProgressReporter? reporter;
            lock (_overallLock)
            {
                if (_overallReporter is null || _overallOutcomeSet)
                {
                    return;
                }

                timer = _overallHeartbeatTimer;
                _overallHeartbeatTimer = null;
                reporter = _overallReporter;
                _overallOutcomeSet = true;
            }

            timer?.Dispose();
            try
            {
                finish(reporter);
            }
            catch (Exception exception)
            {
                LogReportingStopped("RestoreProgressTitle", exception.ToString());
            }
        }

        private void ReportOverallHeartbeat(object? state)
        {
            ReportOverallProgress(final: false);
        }

        private void ReportPackageHeartbeat(object? state)
        {
            ReportPackageProgress(final: false);
        }

        private void LogReportingStopped(string titleResourceName, string reason)
        {
            try
            {
                _log?.LogVerbose(FormatResourceString(
                    "RestoreProgressReportingStopped",
                    GetResourceString(titleResourceName),
                    reason));
            }
            catch (Exception)
            {
                // Logging can fail after the task has returned. Progress reporting must not fail the restore.
            }
        }

        private static void TryDispose(ITaskProgressReporter? reporter)
        {
            try
            {
                reporter?.Dispose();
            }
            catch (Exception)
            {
                // Disposing the reporter abandons the operation. Progress reporting must not fail the restore.
            }
        }

        private static string FormatResourceString(string name, params object[] args)
        {
            return string.Format(CultureInfo.CurrentCulture, GetResourceString(name), args);
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
            // Show the longest-running install, because that is the package that holds the line still.
            InFlightPackage? oldest = null;
            foreach (KeyValuePair<PackageProgressIdentity, InFlightPackage> entry in _inFlightPackages)
            {
                if (oldest is null || entry.Value.StartTimestamp < oldest.Value.StartTimestamp)
                {
                    oldest = entry.Value;
                }
            }

            if (oldest is InFlightPackage package)
            {
                return FormatResourceString("RestoreProgressInstallingPackage", package.PackageId, package.PackageVersion);
            }

            return GetResourceString("RestoreProgressPackagesInstalled");
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

        private readonly struct InFlightPackage
        {
            internal InFlightPackage(string packageId, string packageVersion, long startTimestamp)
            {
                PackageId = packageId;
                PackageVersion = packageVersion;
                StartTimestamp = startTimestamp;
            }

            internal string PackageId { get; }

            internal string PackageVersion { get; }

            internal long StartTimestamp { get; }
        }

        private enum PackageProgressState
        {
            Started,
            Completed
        }
    }
}

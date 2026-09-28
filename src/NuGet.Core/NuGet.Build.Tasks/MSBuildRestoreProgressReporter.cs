// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Threading;
using Microsoft.Build.Framework;
using NuGet.Commands;

namespace NuGet.Build.Tasks
{
    /// <summary>
    /// Reports restore progress through MSBuild's task progress reporting protocol.
    /// </summary>
    /// <remarks>
    /// <see cref="ITaskProgressReporter"/> members never throw and are safe to call concurrently, so this
    /// class does not guard its own calls into the engine. It still keeps its own thread-safe bookkeeping
    /// for restore-specific state the engine does not know about: which phase each project is in, and
    /// which unique packages are in flight. A bug in that bookkeeping (for example, a start/complete
    /// mismatch, or a formatting failure) can still throw; <see cref="FailSafeRestoreOperationProgressReporter"/>
    /// is the safety net for that, so restore never fails because of a progress-reporting bug.
    /// </remarks>
    internal sealed class MSBuildRestoreProgressReporter : IRestoreOperationProgressReporter, IDisposable
    {
        private readonly IBuildEngine10? _buildEngine;
        private readonly Common.ILogger? _log;
        private readonly ITaskProgressReporter? _overallReporter;
        private readonly object _packageReporterGate = new();
        private readonly ConcurrentDictionary<PackageProgressIdentity, PackageProgressState> _packageProgress = new();
        private readonly ConcurrentDictionary<PackageProgressIdentity, InFlightPackage> _inFlightPackages = new();
        private ITaskProgressReporter? _packageReporter;
        private int _completedProjects;
        private int _totalProjects;
        private int _projectsResolving;
        private int _projectsInstalling;
        private int _projectsCommitting;
        private int _projectsUpToDate;
        private int _projectsRemainingResolution;

        // Gate-only counters: they decide when the package operation can finish. The visible
        // Completed/Total shown on screen live in the engine's reporter, not here.
        private long _packagesTotal;
        private long _packagesCompleted;
        private string? _lastCompletedProject;

        internal MSBuildRestoreProgressReporter(IBuildEngine? buildEngine, Common.ILogger? log = null)
        {
            _buildEngine = buildEngine as IBuildEngine10;
            _log = log;

            _overallReporter = _buildEngine?.EngineServices.CreateTaskProgressReporter(
                GetResourceString("RestoreProgressTitle"),
                TaskProgressUnit.Items);
            _overallReporter?.SetStatusProvider(GetOverallStatus);
        }

        public void Start(int totalProjects)
        {
            Interlocked.Exchange(ref _totalProjects, totalProjects);
            Interlocked.Exchange(ref _projectsResolving, totalProjects);
            Interlocked.Exchange(ref _projectsRemainingResolution, totalProjects);
            _overallReporter?.SetTotal(totalProjects > 0 ? totalProjects : null);
        }

        public void StartProject(string projectPath)
        {
            // No counter changes here; the status provider already reflects the current phase mix.
        }

        public void StartPackageInstallBatch(int packageCount)
        {
            if (packageCount <= 0)
            {
                return;
            }

            Interlocked.Decrement(ref _projectsResolving);
            Interlocked.Increment(ref _projectsInstalling);
        }

        public bool TryStartPackageInstall(string packageId, string packageVersion)
        {
            if (_buildEngine is null)
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
            EnsurePackageReporter()?.AddToTotal(1);
            return true;
        }

        public void CompletePackageInstall(string packageId, string packageVersion)
        {
            var identity = new PackageProgressIdentity(packageId, packageVersion);
            if (!_packageProgress.TryUpdate(identity, PackageProgressState.Completed, PackageProgressState.Started))
            {
                // A start/complete mismatch is a NuGet-side bookkeeping bug, not a reporter failure.
                // Log it and continue; do not count it, and do not disturb the rest of the operation.
                _log?.LogVerbose(FormatResourceString("RestoreProgressPackageMismatch", packageId, packageVersion));
                return;
            }

            _inFlightPackages.TryRemove(identity, out _);
            Interlocked.Increment(ref _packagesCompleted);
            Volatile.Read(ref _packageReporter)?.Increment();
            TryCompletePackageOperation();
        }

        public void EndPackageInstallBatch()
        {
            Interlocked.Decrement(ref _projectsInstalling);
            Interlocked.Increment(ref _projectsResolving);
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
                _overallReporter?.Increment();
                Volatile.Write(ref _lastCompletedProject, Path.GetFileName(projectPath));
            }

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
            Volatile.Read(ref _packageReporter)?.Complete();
            _overallReporter?.Complete();
        }

        internal void Cancel()
        {
            Volatile.Read(ref _packageReporter)?.Cancel();
            _overallReporter?.Cancel();
        }

        internal void Fail()
        {
            Volatile.Read(ref _packageReporter)?.Fail();
            _overallReporter?.Fail();
        }

        /// <summary>
        /// Ends both operations with the outcome that matches how the task finished.
        /// </summary>
        internal void Finish(bool succeeded, CancellationToken cancellationToken)
        {
            Volatile.Read(ref _packageReporter)?.Finish(succeeded, cancellationToken);
            _overallReporter?.Finish(succeeded, cancellationToken);
        }

        public void Dispose()
        {
            Volatile.Read(ref _packageReporter)?.Dispose();
            _overallReporter?.Dispose();
        }

        /// <summary>
        /// Creates the package reporter on first use. Multiple projects can reach this concurrently for
        /// the very first package candidate in the restore, so creation is guarded; every later call is
        /// a lock-free read.
        /// </summary>
        private ITaskProgressReporter? EnsurePackageReporter()
        {
            ITaskProgressReporter? reporter = Volatile.Read(ref _packageReporter);
            if (reporter is not null || _buildEngine is null)
            {
                return reporter;
            }

            lock (_packageReporterGate)
            {
                reporter = Volatile.Read(ref _packageReporter);
                if (reporter is null)
                {
                    reporter = _buildEngine.EngineServices.CreateTaskProgressReporter(
                        GetResourceString("RestoreProgressPackagesTitle"),
                        TaskProgressUnit.Items);
                    reporter?.SetStatusProvider(GetPackageProgressStatus);
                    Volatile.Write(ref _packageReporter, reporter);
                }
            }

            return reporter;
        }

        /// <summary>
        /// Finishes the package operation as soon as no project can produce another install batch: every
        /// project is past graph resolution, and every known package has finished its first install check.
        /// A later, unexpected batch cannot reopen a finished operation; the engine drops updates to a
        /// closed reporter, and the batch is still visible through the overall phase counts.
        /// </summary>
        private void TryCompletePackageOperation()
        {
            if (Volatile.Read(ref _projectsRemainingResolution) == 0 &&
                Volatile.Read(ref _packagesCompleted) >= Volatile.Read(ref _packagesTotal))
            {
                Volatile.Read(ref _packageReporter)?.Complete();
            }
        }

        private static string FormatResourceString(string name, params object[] args)
        {
            return string.Format(CultureInfo.CurrentCulture, GetResourceString(name), args);
        }

        private string? GetOverallStatus()
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

        private string? GetPackageProgressStatus()
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

            return Volatile.Read(ref _projectsRemainingResolution) > 0
                ? GetResourceString("RestoreProgressWaitingForDependencies")
                : GetResourceString("RestoreProgressPackagesInstalled");
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

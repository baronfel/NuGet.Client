// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Threading;
using NuGet.Common;

namespace NuGet.Commands
{
    /// <summary>
    /// Isolates restore from failures in an <see cref="IRestoreOperationProgressReporter"/>.
    /// The first failure is logged at verbose level and all later progress calls are ignored.
    /// </summary>
    internal sealed class FailSafeRestoreOperationProgressReporter : IRestoreOperationProgressReporter
    {
        private readonly IRestoreOperationProgressReporter _inner;
        private readonly ILogger _log;
        private int _failed;

        private FailSafeRestoreOperationProgressReporter(IRestoreOperationProgressReporter inner, ILogger log)
        {
            _inner = inner;
            _log = log;
        }

        internal static IRestoreOperationProgressReporter? Create(IRestoreProgressReporter? reporter, ILogger log)
        {
            return reporter switch
            {
                null => null,
                FailSafeRestoreOperationProgressReporter failSafe => failSafe,
                IRestoreOperationProgressReporter operationReporter => new FailSafeRestoreOperationProgressReporter(operationReporter, log),
                _ => null
            };
        }

        public void Start(int totalProjects) => Invoke(static (reporter, count) => reporter.Start(count), totalProjects);

        public void StartProject(string projectPath) => Invoke(static (reporter, path) => reporter.StartProject(path), projectPath);

        public void CompleteProject(string projectPath, bool commitStarted, bool commitSucceeded, bool isNoOp)
        {
            Invoke(
                static (reporter, state) => reporter.CompleteProject(state.projectPath, state.commitStarted, state.commitSucceeded, state.isNoOp),
                (projectPath, commitStarted, commitSucceeded, isNoOp));
        }

        public void StartPackageInstallBatch(int packageCount) => Invoke(static (reporter, count) => reporter.StartPackageInstallBatch(count), packageCount);

        public bool TryStartPackageInstall(string packageId, string packageVersion)
        {
            if (Volatile.Read(ref _failed) != 0)
            {
                return false;
            }

            try
            {
                return _inner.TryStartPackageInstall(packageId, packageVersion);
            }
            catch (Exception exception) when (IsReporterFailure(exception))
            {
                OnFailure(exception);
                return false;
            }
        }

        public void CompletePackageInstall(string packageId, string packageVersion)
        {
            Invoke(static (reporter, state) => reporter.CompletePackageInstall(state.packageId, state.packageVersion), (packageId, packageVersion));
        }

        public void EndPackageInstallBatch() => Invoke(static (reporter, _) => reporter.EndPackageInstallBatch(), 0);

        public void StartProjectCommit(bool isNoOp) => Invoke(static (reporter, noOp) => reporter.StartProjectCommit(noOp), isNoOp);

        public void StartProjectUpdate(string projectPath, IReadOnlyList<string> updatedFiles)
        {
            Invoke(static (reporter, state) => reporter.StartProjectUpdate(state.projectPath, state.updatedFiles), (projectPath, updatedFiles));
        }

        public void EndProjectUpdate(string projectPath, IReadOnlyList<string> updatedFiles)
        {
            Invoke(static (reporter, state) => reporter.EndProjectUpdate(state.projectPath, state.updatedFiles), (projectPath, updatedFiles));
        }

        private void Invoke<TState>(Action<IRestoreOperationProgressReporter, TState> action, TState state)
        {
            if (Volatile.Read(ref _failed) != 0)
            {
                return;
            }

            try
            {
                action(_inner, state);
            }
            catch (Exception exception) when (IsReporterFailure(exception))
            {
                OnFailure(exception);
            }
        }

        [SuppressMessage(
            "Design",
            "CA1031:DoNotCatchGeneralExceptionTypes",
            Justification = "Progress reporting must never fail a restore.")]
        private void OnFailure(Exception exception)
        {
            if (Interlocked.Exchange(ref _failed, 1) != 0)
            {
                return;
            }

            try
            {
                _log.LogVerbose(string.Format(
                    CultureInfo.CurrentCulture,
                    Strings.Log_RestoreProgressReportingFailed,
                    exception.ToString()));
            }
            catch (Exception)
            {
            }
        }

        private static bool IsReporterFailure(Exception exception)
        {
            return exception is not OutOfMemoryException;
        }
    }
}

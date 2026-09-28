// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace NuGet.Commands
{
    /// <summary>
    /// Reports progress for the complete restore operation, including projects that do not update files.
    /// </summary>
    public interface IRestoreOperationProgressReporter : IRestoreProgressReporter
    {
        /// <summary>
        /// Starts a restore operation with the exact number of projects that will be processed.
        /// </summary>
        /// <param name="totalProjects">The number of projects that will be processed.</param>
        void Start(int totalProjects);

        /// <summary>
        /// Reports that restore has started processing a project.
        /// </summary>
        /// <param name="projectPath">The project path.</param>
        void StartProject(string projectPath);

        /// <summary>
        /// Reports that restore has finished processing a project.
        /// </summary>
        /// <param name="projectPath">The project path.</param>
        /// <param name="commitStarted">Whether the project reached its commit phase.</param>
        /// <param name="commitSucceeded">Whether the project commit completed successfully.</param>
        /// <param name="isNoOp">Whether the project restore was a no-op.</param>
        void CompleteProject(string projectPath, bool commitStarted, bool commitSucceeded, bool isNoOp);

        /// <summary>
        /// Reports that a project has started installing a batch of package candidates.
        /// </summary>
        /// <param name="packageCount">The number of package candidates in the batch.</param>
        void StartPackageInstallBatch(int packageCount);

        /// <summary>
        /// Reports the start of a package candidate installation.
        /// </summary>
        /// <param name="packageId">The package ID.</param>
        /// <param name="packageVersion">The package version.</param>
        void ReportPackageInstall(string packageId, string packageVersion);

        /// <summary>
        /// Reports that a package candidate installation attempt has finished.
        /// </summary>
        void CompletePackageInstall();

        /// <summary>
        /// Reports that a project has finished installing a package batch.
        /// </summary>
        void EndPackageInstallBatch();

        /// <summary>
        /// Reports that a project has finished resolving and entered the commit phase.
        /// </summary>
        /// <param name="isNoOp">Whether the project restore was a no-op.</param>
        void StartProjectCommit(bool isNoOp);
    }
}

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
        void CompleteProject(string projectPath);

        /// <summary>
        /// Reports that a package download is starting.
        /// </summary>
        /// <param name="packageId">The package ID.</param>
        /// <param name="packageVersion">The package version.</param>
        void ReportPackageDownload(string packageId, string packageVersion);
    }
}

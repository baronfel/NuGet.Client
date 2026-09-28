// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Build.Framework;
using NuGet.Test.Utility;
using Xunit;

namespace NuGet.Build.Tasks.Test
{
    public class MSBuildRestoreProgressReporterTests
    {
        private const string PackagesTitle = "Installing packages";
        private const string RestoreTitle = "Restoring projects";

        [Fact]
        public void CompletePackageInstall_WithoutMatchingStart_StopsPackageProgressAndRestoreProgressContinues()
        {
            var engine = new ProgressBuildEngine();
            var log = new TestLogger();

            using (var reporter = new MSBuildRestoreProgressReporter(engine, log))
            {
                reporter.Start(1);
                reporter.StartProject("project1.csproj");
                reporter.StartPackageInstallBatch(1);
                Assert.True(reporter.TryStartPackageInstall("a", "1.0.0"));

                // The mismatch is a progress bookkeeping bug. It must not throw into restore.
                reporter.CompletePackageInstall("b", "1.0.0");

                Assert.False(reporter.TryStartPackageInstall("c", "1.0.0"));
                reporter.CompletePackageInstall("a", "1.0.0");
                reporter.EndPackageInstallBatch();
                reporter.StartProjectCommit(isNoOp: false);
                reporter.CompleteProject("project1.csproj", commitStarted: true, commitSucceeded: true, isNoOp: false);
                reporter.Complete();
            }

            RecordingProgressReporter packages = engine.Reporters.Single(r => r.Title == PackagesTitle);
            Assert.Equal("Abandoned", packages.Outcome);
            Assert.All(packages.Updates, update => Assert.Equal(1, update.Total));

            RecordingProgressReporter restore = engine.Reporters.Single(r => r.Title == RestoreTitle);
            Assert.Equal("Completed", restore.Outcome);
            Assert.Equal(1, restore.Updates.Last().Completed);
            Assert.Equal(1, restore.Updates.Last().Total);
            Assert.Contains(log.Messages, message => message.Contains("b 1.0.0"));
        }

        [Fact]
        public void Report_WhenEngineReporterThrows_StopsThatOperationAndDoesNotThrow()
        {
            var engine = new ProgressBuildEngine(throwOnReportTitle: PackagesTitle);
            var log = new TestLogger();

            using (var reporter = new MSBuildRestoreProgressReporter(engine, log))
            {
                reporter.Start(1);
                reporter.StartPackageInstallBatch(1);
                reporter.TryStartPackageInstall("a", "1.0.0");
                reporter.CompletePackageInstall("a", "1.0.0");
                reporter.EndPackageInstallBatch();
                reporter.StartProjectCommit(isNoOp: false);
                reporter.CompleteProject("project1.csproj", commitStarted: true, commitSucceeded: true, isNoOp: false);
                reporter.Complete();
            }

            Assert.Equal("Abandoned", engine.Reporters.Single(r => r.Title == PackagesTitle).Outcome);
            Assert.Equal("Completed", engine.Reporters.Single(r => r.Title == RestoreTitle).Outcome);
            Assert.Contains(log.Messages, message => message.Contains("Simulated progress failure."));
        }

        [Fact]
        public void Report_WhenContentDoesNotChange_SkipsUpdateAndReportsEveryChange()
        {
            var engine = new ProgressBuildEngine();

            using (var reporter = new MSBuildRestoreProgressReporter(engine))
            {
                reporter.Start(2);
                reporter.StartProject("project1.csproj");
                reporter.StartProject("project2.csproj");
                reporter.StartProjectCommit(isNoOp: false);
                reporter.CompleteProject("project1.csproj", commitStarted: true, commitSucceeded: true, isNoOp: false);

                RecordingProgressReporter restore = engine.Reporters.Single(r => r.Title == RestoreTitle);
                IReadOnlyList<TaskProgressUpdate> updates = restore.Updates;

                // Initial status, Start, commit, and completion each change content; StartProject does not.
                Assert.Equal(4, updates.Count);
                Assert.Equal(1, updates.Last().Completed);
                Assert.Equal(2, updates.Last().Total);
                for (int i = 1; i < updates.Count; i++)
                {
                    Assert.False(
                        updates[i].Completed == updates[i - 1].Completed &&
                        updates[i].Total == updates[i - 1].Total &&
                        updates[i].Status == updates[i - 1].Status);
                }
            }
        }

        private sealed class ProgressBuildEngine : TestBuildEngine, IBuildEngine10
        {
            private readonly RecordingEngineServices _engineServices;

            public ProgressBuildEngine(string? throwOnReportTitle = null)
            {
                _engineServices = new RecordingEngineServices(throwOnReportTitle);
            }

            public IReadOnlyList<RecordingProgressReporter> Reporters => _engineServices.Reporters;

            public bool AllowFailureWithoutError { get; set; }

            public EngineServices EngineServices => _engineServices;

            public bool ShouldTreatWarningAsError(string warningCode) => false;

            public int RequestCores(int requestedCores) => requestedCores;

            public void ReleaseCores(int coresToRelease)
            {
            }
        }

        private sealed class RecordingEngineServices : EngineServices
        {
            private readonly string? _throwOnReportTitle;
            private readonly List<RecordingProgressReporter> _reporters = new();

            public RecordingEngineServices(string? throwOnReportTitle)
            {
                _throwOnReportTitle = throwOnReportTitle;
            }

            public IReadOnlyList<RecordingProgressReporter> Reporters
            {
                get
                {
                    lock (_reporters)
                    {
                        return _reporters.ToList();
                    }
                }
            }

            public override ITaskProgressReporter CreateTaskProgressReporter(string title, TaskProgressUnit unit = TaskProgressUnit.Unspecified)
            {
                var reporter = new RecordingProgressReporter(title, throwOnReport: title == _throwOnReportTitle);
                lock (_reporters)
                {
                    _reporters.Add(reporter);
                }

                return reporter;
            }
        }

        private sealed class RecordingProgressReporter : ITaskProgressReporter
        {
            private readonly bool _throwOnReport;
            private readonly List<TaskProgressUpdate> _updates = new();

            public RecordingProgressReporter(string title, bool throwOnReport)
            {
                Title = title;
                _throwOnReport = throwOnReport;
            }

            public string Title { get; }

            public string? Outcome { get; private set; }

            public IReadOnlyList<TaskProgressUpdate> Updates
            {
                get
                {
                    lock (_updates)
                    {
                        return _updates.ToList();
                    }
                }
            }

            public void Report(TaskProgressUpdate value)
            {
                if (_throwOnReport)
                {
                    throw new InvalidOperationException("Simulated progress failure.");
                }

                lock (_updates)
                {
                    _updates.Add(value);
                }
            }

            public void Complete(string? summary = null) => Outcome ??= "Completed";

            public void Cancel(string? summary = null) => Outcome ??= "Canceled";

            public void Fail(string? summary = null) => Outcome ??= "Failed";

            public void Dispose() => Outcome ??= "Abandoned";
        }
    }
}

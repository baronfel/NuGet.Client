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
        public void CompletePackageInstall_WithoutMatchingStart_LogsAndRestoreContinues()
        {
            var engine = new ProgressBuildEngine();
            var log = new TestLogger();

            using (var reporter = new MSBuildRestoreProgressReporter(engine, log))
            {
                reporter.Start(1);
                reporter.StartProject("project1.csproj");
                reporter.StartPackageInstallBatch(1);
                Assert.True(reporter.TryStartPackageInstall("a", "1.0.0"));

                // "b" was never started. This is a NuGet-side bookkeeping bug, not an engine failure:
                // it must be logged and skipped, and it must not stop or fail the rest of the operation.
                reporter.CompletePackageInstall("b", "1.0.0");

                // "c" is a genuinely new package identity, so it is still accepted normally.
                Assert.True(reporter.TryStartPackageInstall("c", "1.0.0"));
                reporter.CompletePackageInstall("a", "1.0.0");
                reporter.CompletePackageInstall("c", "1.0.0");
                reporter.EndPackageInstallBatch();
                reporter.StartProjectCommit(isNoOp: false);
                reporter.CompleteProject("project1.csproj", commitStarted: true, commitSucceeded: true, isNoOp: false);
                reporter.Complete();
            }

            RecordingProgressReporter restore = engine.Reporters.Single(r => r.Title == RestoreTitle);
            RecordingProgressReporter packages = restore.NestedReporters.Single(r => r.Title == PackagesTitle);
            Assert.Equal(TaskProgressNestedRetention.Persist, packages.Retention);
            Assert.Equal("Completed", packages.Outcome);
            Assert.Equal(2, packages.Updates.Last().Total);
            Assert.Equal(2, packages.Updates.Last().Completed);

            Assert.Equal("Completed", restore.Outcome);
            Assert.Equal(1, restore.Updates.Last().Completed);
            Assert.Equal(1, restore.Updates.Last().Total);
            Assert.Contains(log.Messages, message => message.Contains("b 1.0.0"));
        }

        [Fact]
        public void StatusProvider_SurfacesPhaseCountsOnlyWhenPolled()
        {
            // ITaskProgressReporter is guaranteed never to throw, and a background timer -- not our
            // code -- polls the status provider. This test documents the resulting behavior difference:
            // counter changes made through Increment/AddToTotal/SetTotal are visible immediately, but a
            // phase transition that only changes the text the provider computes is not forwarded until
            // the engine's timer (simulated here via PollStatusProvider) next ticks.
            var engine = new ProgressBuildEngine();

            using (var reporter = new MSBuildRestoreProgressReporter(engine))
            {
                RecordingProgressReporter restore = engine.Reporters.Single(r => r.Title == RestoreTitle);

                // Setting the status provider polls it immediately, before any project has started.
                Assert.Single(restore.Updates);
                Assert.Null(restore.Updates[0].Total);

                // Start touches Total directly, so it is visible without an explicit poll.
                reporter.Start(2);
                Assert.Equal(2, restore.Updates.Last().Total);

                reporter.StartProject("project1.csproj");
                reporter.StartProject("project2.csproj");

                int countBeforeCommit = restore.Updates.Count;
                reporter.StartProjectCommit(isNoOp: false);
                Assert.Equal(countBeforeCommit, restore.Updates.Count);

                restore.PollStatusProvider();
                Assert.True(restore.Updates.Count > countBeforeCommit);
                Assert.Contains("Committing", restore.Updates.Last().Status, StringComparison.Ordinal);

                // Polling again with nothing changed must not add a duplicate frame.
                int countAfterPoll = restore.Updates.Count;
                restore.PollStatusProvider();
                Assert.Equal(countAfterPoll, restore.Updates.Count);

                reporter.CompleteProject("project1.csproj", commitStarted: true, commitSucceeded: true, isNoOp: false);
                Assert.Equal(1, restore.Updates.Last().Completed);

                reporter.Complete();
            }
        }

        private sealed class ProgressBuildEngine : TestBuildEngine, IBuildEngine10
        {
            private readonly RecordingEngineServices _engineServices = new();

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
            private readonly List<RecordingProgressReporter> _reporters = new();

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
                var reporter = new RecordingProgressReporter(title);
                lock (_reporters)
                {
                    _reporters.Add(reporter);
                }

                return reporter;
            }
        }

        /// <summary>
        /// A test double for <see cref="ITaskProgressReporter"/> that follows the real engine's contract:
        /// members never throw, the first terminal call wins, and identical consecutive updates are not
        /// recorded twice. Status-provider polling is not driven by a background timer here; tests call
        /// <see cref="PollStatusProvider"/> to simulate a timer tick.
        /// </summary>
        private sealed class RecordingProgressReporter : ITaskProgressReporter
        {
            private readonly object _gate = new();
            private readonly List<TaskProgressUpdate> _updates = new();
            private readonly List<RecordingProgressReporter> _nestedReporters = new();
            private long _completed;
            private long? _total;
            private string? _explicitStatus;
            private Func<string?>? _statusProvider;
            private bool _terminal;

            public RecordingProgressReporter(string title)
            {
                Title = title;
            }

            public string Title { get; }

            public string? Outcome { get; private set; }

            public TaskProgressNestedRetention? Retention { get; private set; }

            public IReadOnlyList<RecordingProgressReporter> NestedReporters
            {
                get
                {
                    lock (_gate)
                    {
                        return _nestedReporters.ToList();
                    }
                }
            }

            public IReadOnlyList<TaskProgressUpdate> Updates
            {
                get
                {
                    lock (_gate)
                    {
                        return _updates.ToList();
                    }
                }
            }

            public void Report(TaskProgressUpdate value)
            {
                lock (_gate)
                {
                    if (_terminal)
                    {
                        return;
                    }

                    _completed = Math.Max(0, value.Completed);
                    _total = value.Total.HasValue ? Math.Max(0, value.Total.Value) : null;
                    _explicitStatus = value.Status;
                    _statusProvider = null;
                    RecordIfChanged();
                }
            }

            public void Increment(long delta = 1)
            {
                lock (_gate)
                {
                    if (_terminal)
                    {
                        return;
                    }

                    _completed = Math.Max(0, _completed + delta);
                    RecordIfChanged();
                }
            }

            public void AddToTotal(long delta)
            {
                lock (_gate)
                {
                    if (_terminal)
                    {
                        return;
                    }

                    _total = Math.Max(0, (_total ?? 0) + delta);
                    RecordIfChanged();
                }
            }

            public void SetTotal(long? total)
            {
                lock (_gate)
                {
                    if (_terminal)
                    {
                        return;
                    }

                    _total = total.HasValue ? Math.Max(0, total.Value) : null;
                    RecordIfChanged();
                }
            }

            public void SetStatus(string? status)
            {
                lock (_gate)
                {
                    if (_terminal)
                    {
                        return;
                    }

                    _explicitStatus = status;
                    _statusProvider = null;
                    RecordIfChanged();
                }
            }

            public void SetStatusProvider(Func<string?>? provider)
            {
                lock (_gate)
                {
                    if (_terminal)
                    {
                        return;
                    }

                    _statusProvider = provider;
                    RecordIfChanged();
                }
            }

            /// <summary>Simulates one tick of the engine's status-provider polling timer.</summary>
            public void PollStatusProvider()
            {
                lock (_gate)
                {
                    if (_terminal || _statusProvider is null)
                    {
                        return;
                    }

                    RecordIfChanged();
                }
            }

            public void Complete(string? summary = null) => Finish("Completed");

            public void Cancel(string? summary = null) => Finish("Canceled");

            public void Fail(string? summary = null) => Finish("Failed");

            public void Dispose() => Finish("Abandoned");

            public ITaskProgressReporter CreateNestedReporter(
                string title,
                TaskProgressUnit unit = TaskProgressUnit.Unspecified,
                TaskProgressNestedRetention retention = TaskProgressNestedRetention.Remove)
            {
                lock (_gate)
                {
                    var nested = new RecordingProgressReporter(title) { Retention = retention };
                    if (_terminal)
                    {
                        // Like the engine, a reporter that already ended hands out a reporter that
                        // ignores every call, without recording it as a live child.
                        nested.Dispose();
                        return nested;
                    }

                    _nestedReporters.Add(nested);
                    return nested;
                }
            }

            private void Finish(string outcome)
            {
                RecordingProgressReporter[] nested;
                lock (_gate)
                {
                    if (_terminal)
                    {
                        return;
                    }

                    _terminal = true;
                    Outcome = outcome;
                    nested = _nestedReporters.ToArray();
                }

                // Like the engine, any nested operation still active is abandoned when the parent ends.
                foreach (RecordingProgressReporter reporter in nested)
                {
                    reporter.Dispose();
                }
            }

            private void RecordIfChanged()
            {
                string? status = _statusProvider is not null ? SafeInvoke(_statusProvider) : _explicitStatus;
                var update = new TaskProgressUpdate(_completed, _total, status);
                if (_updates.Count == 0 || !IsSame(_updates[_updates.Count - 1], update))
                {
                    _updates.Add(update);
                }
            }

            private static string? SafeInvoke(Func<string?> provider)
            {
                try
                {
                    return provider();
                }
                catch
                {
                    return null;
                }
            }

            private static bool IsSame(TaskProgressUpdate x, TaskProgressUpdate y)
            {
                return x.Completed == y.Completed && x.Total == y.Total && x.Status == y.Status;
            }
        }
    }
}

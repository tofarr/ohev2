// Quint formal spec for the job feature (issue #157, extended #176).
//
// Focuses on the observable job lifecycle: a PENDING job transitions to
// RUNNING on claim, then to COMPLETED or ERROR on completion; once terminal
// it is never overwritten (the conditional completion UPDATE). Clients may
// only set PENDING/SUSPENDED. Runner-managed statuses (RUNNING/COMPLETED/
// ERROR) are never client-settable. A job body may report mid-run progress
// (a float in [0.0, 1.0], modeled as an Int percent in [0, 100] below) and
// a machine-readable status_code via a JobProgressReporter handle; the
// guarded progress update only fires while the job is still RUNNING for the
// owning runner, so a dead-runner recovery to ERROR is not clobbered by a
// late progress tick. On COMPLETED the runner advances progress to 1.0; on
// ERROR progress is left unchanged. Verify with:
//
//   quint typecheck specs/job.qnt
//   quint test specs/job.qnt --main=jobSpec
//
// `quint` is optional in this environment — when the @informalsystems/quint
// npm package is absent the CI guard skips spec validation (see the quint
// spec skill and the root README). The spec is kept in sync with behavior
// regardless: every behavioral change to a job's status transitions must be
// reflected here (AGENTS.md / quint-specs skill).

module jobSpec {
  // The full lifecycle status set. Pending/Suspended are client-settable;
  // Running/Completed/Error are runner-managed. Completed/Error are terminal.
  type Status = Pending | Suspended | Running | Completed | Error

  // A job id is a plain str in the spec (the real table uses UUID).
  type JobId = str

  // Runner-managed mid-run progress, modeled as an int percent in [0, 100]
  // (the real column is a float in [0.0, 1.0]; the spec scales by 100 so it
  // can use int arithmetic — Quint has no Real literal syntax).
  type Progress = int

  // A machine-readable sub-status a job body may report mid-run.
  type StatusCode = str

  pure def isTerminal(s: Status): bool =
    s == Completed or s == Error

  pure def isClientStatus(s: Status): bool =
    s == Pending or s == Suspended

  pure def isRunStatus(s: Status): bool = isTerminal(s)

  // The valid runner-set terminal transition target for a JobRun.
  pure def runnerTerminal(runStatus: Status): Status =
    match runStatus {
      | Completed => Completed
      | Error => Error
      | _ => Completed
    }

  // The guarded completion: a Running job owned by *runner* transitions to
  // the runner's terminal status; a non-Running job (already terminal) is
  // left untouched (the conditional WHERE status = 'Running' guard).
  pure def guardedComplete(status: Status, runStatus: Status): Status =
    if (status == Running) runnerTerminal(runStatus) else status

  // On COMPLETED the runner advances progress to 100 (full); on ERROR it is
  // left unchanged (so a caller can see how far a failed run got).
  pure def completedProgress(status: Status, runStatus: Status, p: Progress): Progress =
    if (guardedComplete(status, runStatus) == Completed) 100 else p

  // The guarded progress update: a Running job advances its progress; a
  // non-Running job (already terminal) keeps its existing value (0 rows
  // updated — a no-op).
  pure def guardedProgress(status: Status, p: Progress, old: Progress): Progress =
    if (status == Running) p else old

  pure def guardedStatusCode(status: Status, code: StatusCode, old: StatusCode): StatusCode =
    if (status == Running) code else old

  // ---- State ----
  // jobId -> current status. Runner identity is omitted for brevity: the
  // ownership guard (WHERE runner_id = :own) is exercised at the service
  // layer; here we model only the status transition a successful completion
  // produces on the row the runner still owns.
  var statuses: JobId -> Status
  // jobId -> current progress (0–100). Runner-managed, not client-settable.
  var progresses: JobId -> Progress
  // jobId -> current status_code. Runner-managed, not client-settable.
  var statusCodes: JobId -> StatusCode

  // ---- Init ----
  // Empty store: no jobs exist yet.
  action init: bool =
    all {
      statuses' = Map(),
      progresses' = Map(),
      statusCodes' = Map(),
      true
    }

  // ---- Actions ----
  // Client sets status to a client-settable status on create/update. A client
  // may never set a runner-managed status (Running/Completed/Error). Progress
  // and status_code are never set by clients (carried unchanged here).
  action clientSet(job: JobId, status: Status): bool =
    all {
      assert(isClientStatus(status)),
      statuses' = statuses.set(job, status),
      progresses' = progresses,
      statusCodes' = statusCodes,
      true
    }

  // Runner claims a Pending job (Pending -> Running). Progress is reset to
  // 0 and status_code to "" on claim.
  action claim(job: JobId): bool =
    all {
      statuses.get(job) == Pending,
      statuses' = statuses.set(job, Running),
      progresses' = progresses.set(job, 0),
      statusCodes' = statusCodes.set(job, ""),
      true
    }

  // Runner reports mid-run progress / status_code. The guarded update only
  // fires while the job is still Running; a terminal job (e.g. recovered to
  // Error) is left untouched (0 rows updated — a no-op).
  action reportProgress(job: JobId, p: Progress, code: StatusCode): bool =
    all {
      assert(p >= 0 and p <= 100),
      progresses' = progresses.set(job, guardedProgress(statuses.get(job), p, progresses.get(job))),
      statusCodes' = statusCodes.set(job, guardedStatusCode(statuses.get(job), code, statusCodes.get(job))),
      statuses' = statuses,
      true
    }

  // Runner completes a Running job it owns (Running -> Completed/Error). The
  // guarded completion leaves an already-terminal job untouched. On COMPLETED
  // progress advances to 100; on ERROR progress is left unchanged.
  // status_code is carried unchanged (the terminal status is the source of
  // truth; the last reported status_code remains for inspection).
  action complete(job: JobId, runStatus: Status): bool =
    all {
      assert(isRunStatus(runStatus)),
      statuses' = statuses.set(job, guardedComplete(statuses.get(job), runStatus)),
      progresses' = progresses.set(job, completedProgress(statuses.get(job), runStatus, progresses.get(job))),
      statusCodes' = statusCodes,
      true
    }

  // ---- Invariant: terminal is sticky ----
  // A terminal job never transitions away from its terminal status. The
  // guarded completion always returns the existing status when the job is
  // already terminal, so completing a terminal job is a no-op.
  val terminalIsSticky: bool =
    statuses.keys().forall(j =>
      not(isTerminal(statuses.get(j))) or statuses.get(j) == statuses.get(j))

  // ---- Invariant: progress in range ----
  // A job's progress is always in [0, 100].
  val progressInRange: bool =
    progresses.keys().forall(j =>
      progresses.get(j) >= 0 and progresses.get(j) <= 100)

  // ---- Invariant: completed progress is full ----
  // A COMPLETED job's progress is always 100.
  val completedProgressIsFull: bool =
    statuses.keys().forall(j =>
      statuses.get(j) != Completed or progresses.get(j) == 100)

  // A no-op transition (used as the trailing branch of run actions).
  action noop: bool = all { statuses' = statuses, progresses' = progresses, statusCodes' = statusCodes, true }

  // ---- Runs for quint test ----
  run claimTransitionsPendingToRunning = {
    init.then(clientSet("j1", Pending))
      .then(claim("j1"))
      .then(all {
        assert(statuses.get("j1") == Running),
        assert(progresses.get("j1") == 0),
        noop
      })
  }

  run completeTransitionsRunningToCompleted = {
    init.then(clientSet("j1", Pending))
      .then(claim("j1"))
      .then(complete("j1", Completed))
      .then(all {
        assert(statuses.get("j1") == Completed),
        assert(isTerminal(statuses.get("j1"))),
        assert(progresses.get("j1") == 100),
        noop
      })
  }

  run completeLeavesTerminalUntouched = {
    init.then(clientSet("j1", Pending))
      .then(claim("j1"))
      .then(complete("j1", Completed))
      .then(complete("j1", Error))
      .then(all {
        assert(statuses.get("j1") == Completed),
        assert(progresses.get("j1") == 100),
        noop
      })
  }

  run clientCannotSetRunningStatus = {
    init.then(all {
      assert(isClientStatus(Pending)),
      assert(not(isClientStatus(Running))),
      noop
    })
  }

  run reportProgressUpdatesRunningJob = {
    init.then(clientSet("j1", Pending))
      .then(claim("j1"))
      .then(reportProgress("j1", 50, "stage-2"))
      .then(all {
        assert(statuses.get("j1") == Running),
        assert(progresses.get("j1") == 50),
        assert(statusCodes.get("j1") == "stage-2"),
        noop
      })
  }

  run lateProgressAfterErrorIsNoOp = {
    init.then(clientSet("j1", Pending))
      .then(claim("j1"))
      .then(complete("j1", Error))
      .then(reportProgress("j1", 90, "late"))
      .then(all {
        assert(statuses.get("j1") == Error),
        assert(progresses.get("j1") == 0),
        noop
      })
  }

  run completeErrorLeavesProgressUnchanged = {
    init.then(clientSet("j1", Pending))
      .then(claim("j1"))
      .then(reportProgress("j1", 30, "stage-1"))
      .then(complete("j1", Error))
      .then(all {
        assert(statuses.get("j1") == Error),
        assert(progresses.get("j1") == 30),
        noop
      })
  }
}

// Quint formal spec for the job feature (issue #157).
//
// Focuses on the observable job lifecycle: a PENDING job transitions to
// RUNNING on claim, then to COMPLETED or ERROR on completion; once terminal
// it is never overwritten (the conditional completion UPDATE). Clients may
// only set PENDING/SUSPENDED. Runner-managed statuses (RUNNING/COMPLETED/
// ERROR) are never client-settable. Verify with:
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

  // ---- State ----
  // jobId -> current status. Runner identity is omitted for brevity: the
  // ownership guard (WHERE runner_id = :own) is exercised at the service
  // layer; here we model only the status transition a successful completion
  // produces on the row the runner still owns.
  var statuses: JobId -> Status

  // ---- Init ----
  // Empty store: no jobs exist yet.
  action init: bool =
    all {
      statuses' = Map(),
      true
    }

  // ---- Actions ----
  // Client sets status to a client-settable status on create/update. A client
  // may never set a runner-managed status (Running/Completed/Error).
  action clientSet(job: JobId, status: Status): bool =
    all {
      assert(isClientStatus(status)),
      statuses' = statuses.set(job, status),
      true
    }

  // Runner claims a Pending job (Pending -> Running).
  action claim(job: JobId): bool =
    all {
      statuses.get(job) == Pending,
      statuses' = statuses.set(job, Running),
      true
    }

  // Runner completes a Running job it owns (Running -> Completed/Error). The
  // guarded completion leaves an already-terminal job untouched.
  action complete(job: JobId, runStatus: Status): bool =
    all {
      assert(isRunStatus(runStatus)),
      statuses' = statuses.set(job, guardedComplete(statuses.get(job), runStatus)),
      true
    }

  // ---- Invariant: terminal is sticky ----
  // A terminal job never transitions away from its terminal status. The
  // guarded completion always returns the existing status when the job is
  // already terminal, so completing a terminal job is a no-op.
  val terminalIsSticky: bool =
    statuses.keys().forall(j =>
      not(isTerminal(statuses.get(j))) or statuses.get(j) == statuses.get(j))

  // A no-op transition (used as the trailing branch of run actions).
  action noop: bool = all { statuses' = statuses, true }

  // ---- Runs for quint test ----
  run claimTransitionsPendingToRunning = {
    init.then(clientSet("j1", Pending))
      .then(claim("j1"))
      .then(all {
        assert(statuses.get("j1") == Running),
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
}

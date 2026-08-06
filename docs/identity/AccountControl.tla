--------------------------- MODULE AccountControl ---------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS Controllers, ControllerWeight

ASSUME /\ Cardinality(Controllers) = 3
       /\ ControllerWeight \in [Controllers -> 1..2]
       /\ Cardinality({c \in Controllers : ControllerWeight[c] = 2}) = 1
       /\ Cardinality({c \in Controllers : ControllerWeight[c] = 1}) = 2

RECURSIVE WeightOf(_)
WeightOf(controllerSet) ==
    IF controllerSet = {}
        THEN 0
        ELSE LET c == CHOOSE member \in controllerSet : TRUE
             IN ControllerWeight[c] + WeightOf(controllerSet \ {c})

VARIABLES active, revoked, threshold, heads, forkVisible,
          lastAccepted, lastKind, lastApprovals, predecessorCount,
          priorActive, priorRevoked, priorThreshold, priorHeads,
          recoveryReplacement, recoveryPreviousActive

vars == <<active, revoked, threshold, heads, forkVisible,
          lastAccepted, lastKind, lastApprovals, predecessorCount,
          priorActive, priorRevoked, priorThreshold, priorHeads,
          recoveryReplacement, recoveryPreviousActive>>

Kinds == {"Init", "AddController", "RevokeController", "ChangePolicy",
          "OpenFork", "ResolveFork", "Recover"}

TypeOK ==
    /\ active \in SUBSET Controllers
    /\ revoked \in SUBSET Controllers
    /\ active \cap revoked = {}
    /\ threshold \in 1..WeightOf(active)
    /\ heads \in 1..2
    /\ forkVisible \in BOOLEAN
    /\ lastAccepted \in BOOLEAN
    /\ lastKind \in Kinds
    /\ lastApprovals \in SUBSET Controllers
    /\ predecessorCount \in Nat
    /\ priorActive \in SUBSET Controllers
    /\ priorRevoked \in SUBSET Controllers
    /\ priorThreshold \in Nat
    /\ priorHeads \in 1..2
    /\ recoveryReplacement \in SUBSET Controllers
    /\ recoveryPreviousActive \in SUBSET Controllers

Init ==
    /\ active = Controllers
    /\ revoked = {}
    /\ threshold = 2
    /\ heads = 1
    /\ forkVisible = FALSE
    /\ lastAccepted = FALSE
    /\ lastKind = "Init"
    /\ lastApprovals = {}
    /\ predecessorCount = 0
    /\ priorActive = active
    /\ priorRevoked = revoked
    /\ priorThreshold = threshold
    /\ priorHeads = heads
    /\ recoveryReplacement = {}
    /\ recoveryPreviousActive = {}

Authorized(approvals) ==
    /\ approvals \in SUBSET active
    /\ approvals \cap revoked = {}
    /\ WeightOf(approvals) >= threshold

RecordAccepted(kind, approvals, predecessors, replacement) ==
    /\ lastAccepted' = TRUE
    /\ lastKind' = kind
    /\ lastApprovals' = approvals
    /\ predecessorCount' = predecessors
    /\ priorActive' = active
    /\ priorRevoked' = revoked
    /\ priorThreshold' = threshold
    /\ priorHeads' = heads
    /\ recoveryReplacement' = replacement
    /\ recoveryPreviousActive' = IF kind = "Recover" THEN active ELSE {}

AddController(c, approvals) ==
    /\ heads = 1
    /\ c \in Controllers \ (active \cup revoked)
    /\ Authorized(approvals)
    /\ active' = active \cup {c}
    /\ RecordAccepted("AddController", approvals, 1, {})
    /\ UNCHANGED <<revoked, threshold, heads, forkVisible>>

RevokeController(c, approvals) ==
    /\ heads = 1
    /\ c \in active
    /\ Authorized(approvals)
    /\ WeightOf(active \ {c}) >= threshold
    /\ active' = active \ {c}
    /\ revoked' = revoked \cup {c}
    /\ RecordAccepted("RevokeController", approvals, 1, {})
    /\ UNCHANGED <<threshold, heads, forkVisible>>

ChangePolicy(newThreshold, approvals) ==
    /\ heads = 1
    /\ newThreshold \in 1..WeightOf(active)
    /\ Authorized(approvals)
    /\ threshold' = newThreshold
    /\ RecordAccepted("ChangePolicy", approvals, 1, {})
    /\ UNCHANGED <<active, revoked, heads, forkVisible>>

OpenFork(approvals) ==
    /\ heads = 1
    /\ Authorized(approvals)
    /\ heads' = 2
    /\ forkVisible' = TRUE
    /\ RecordAccepted("OpenFork", approvals, 1, {})
    /\ UNCHANGED <<active, revoked, threshold>>

ResolveFork(approvals) ==
    /\ heads > 1
    /\ Authorized(approvals)
    /\ heads' = 1
    /\ forkVisible' = FALSE
    /\ RecordAccepted("ResolveFork", approvals, heads, {})
    /\ UNCHANGED <<active, revoked, threshold>>

Recover(replacement, newThreshold) ==
    /\ heads = 1
    /\ replacement \in SUBSET Controllers
    /\ replacement # {}
    /\ replacement \cap revoked = {}
    /\ newThreshold \in 1..WeightOf(replacement)
    /\ active' = replacement
    /\ revoked' = revoked \cup (active \ replacement)
    /\ threshold' = newThreshold
    /\ forkVisible' = FALSE
    /\ RecordAccepted("Recover", {}, 1, replacement)
    /\ UNCHANGED heads

Next ==
    \/ \E c \in Controllers, approvals \in SUBSET Controllers :
        AddController(c, approvals)
    \/ \E c \in Controllers, approvals \in SUBSET Controllers :
        RevokeController(c, approvals)
    \/ \E newThreshold \in 1..WeightOf(Controllers),
          approvals \in SUBSET Controllers :
        ChangePolicy(newThreshold, approvals)
    \/ \E approvals \in SUBSET Controllers : OpenFork(approvals)
    \/ \E approvals \in SUBSET Controllers : ResolveFork(approvals)
    \/ \E replacement \in SUBSET Controllers,
          newThreshold \in 1..WeightOf(Controllers) :
        Recover(replacement, newThreshold)

RevokedControllersCannotAuthorize ==
    ~lastAccepted
        \/ /\ lastApprovals \in SUBSET priorActive
           /\ lastApprovals \cap priorRevoked = {}

PolicyChangesUsePreviousPolicy ==
    ~lastAccepted \/ lastKind # "ChangePolicy"
        \/ WeightOf(lastApprovals) >= priorThreshold

ForksAreDetectable ==
    /\ (heads > 1) = forkVisible
    /\ ~lastAccepted \/ priorHeads = 1 \/ lastKind = "ResolveFork"

ThresholdRequirementsPreserved ==
    /\ threshold > 0
    /\ threshold <= WeightOf(active)
    /\ active \cap revoked = {}

RecoveryDoesNotRetainOldControllers ==
    ~lastAccepted \/ lastKind # "Recover"
        \/ /\ active = recoveryReplacement
           /\ (recoveryPreviousActive \ recoveryReplacement) \subseteq revoked

AcceptedEventsHaveUniquePredecessor ==
    ~lastAccepted
        \/ IF lastKind = "ResolveFork"
              THEN /\ predecessorCount = priorHeads
                   /\ priorHeads > 1
              ELSE predecessorCount = 1

Safety ==
    /\ TypeOK
    /\ RevokedControllersCannotAuthorize
    /\ PolicyChangesUsePreviousPolicy
    /\ ForksAreDetectable
    /\ ThresholdRequirementsPreserved
    /\ RecoveryDoesNotRetainOldControllers
    /\ AcceptedEventsHaveUniquePredecessor

Spec == Init /\ [][Next]_vars

=============================================================================

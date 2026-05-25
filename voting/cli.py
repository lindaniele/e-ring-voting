"""
``evote`` — command-line interface for the v0.3 voting system.

Subcommands map to the principal APIs. Key files are PEM-encoded; logs and
sidecars are JSON Lines. Pass ``--help`` to any subcommand for details.

Typical flow (1-of-1 cohort, no witnesses — the v0.2 single-publisher
model — is the default; pass ``--threshold`` and ``--cohort-size`` for
real decentralisation):

::

    evote manager-keygen   --sk-out msk.pem --pk-out mpk.pem
    evote setup            --log log.jsonl --sk msk.pem --title ... --options ...
    evote voter-keygen     --out voter-0.json
    evote register         --log log.jsonl --sk msk.pem --voter-pk ... --handle ...
    evote publish-ring     --log log.jsonl --sk msk.pem
    evote vote             --log log.jsonl --voter-key voter-0.json --choice yes \\
                           --manager-sk msk.pem
    evote close            --log log.jsonl --sk msk.pem
    evote tally            --log log.jsonl --publish --sk msk.pem
    evote audit            --log log.jsonl

For a threshold cohort or witness federation, use the
``cohort-keygen``, ``setup-cohort``, ``sign-pending``, ``commit-pending``,
``witness-keygen``, and ``witness-checkpoint`` subcommands instead.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from base64 import b64decode, b64encode
from pathlib import Path
from typing import List, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from voting import auditor as auditor_mod
from voting import manager as mgr
from voting import voter as vt
from voting import witness as wit
from voting.log import (
    BulletinBoard,
    PublisherCohort,
    commit_pending,
    cosign_pending,
    load_publisher_pk,
    load_publisher_sk,
    pk_from_raw,
    pk_raw,
    propose_entry,
    save_publisher_pk,
    save_publisher_sk,
)
from voting.records import parse_payload, ElectionSetup


def _err(msg: str, code: int = 1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


# --------------------------------------------------------------------------- #
# Key helpers                                                                 #
# --------------------------------------------------------------------------- #


def _load_cohort_from_setup(log_path: Path) -> PublisherCohort:
    """Read the genesis entry to recover the cohort identity."""
    log = BulletinBoard(log_path)
    entries = log.read_all()
    if not entries:
        _err(f"log {log_path} is empty; run `evote setup` first")
    setup = parse_payload(entries[0].payload)
    if not isinstance(setup, ElectionSetup):
        _err("first entry of the log is not an ElectionSetup")
    pks = [pk_from_raw(b64decode(s)) for s in setup.cohort_pks_b64]
    return PublisherCohort(pks=pks, threshold=setup.threshold)


def _build_cohort_spec(
    sk_paths: List[Path], log_path: Path | None = None
) -> mgr.CohortSpec:
    """
    Assemble a :class:`CohortSpec` from a list of cohort sk PEM files and
    (optionally) the cohort identity recovered from an existing log.
    """
    sks = [load_publisher_sk(p) for p in sk_paths]
    if log_path is not None and log_path.exists():
        pub = _load_cohort_from_setup(log_path)
        # Figure out each sk's index in the cohort.
        signers: list[tuple[int, ed25519.Ed25519PrivateKey]] = []
        for sk in sks:
            pkb = pk_raw(sk.public_key())
            for i, pk in enumerate(pub.pks):
                if pk_raw(pk) == pkb:
                    signers.append((i, sk))
                    break
            else:
                _err("an --sk does not match any cohort key in the log's setup")
        return mgr.CohortSpec(
            pks=list(pub.pks), threshold=pub.threshold, sks=signers
        )
    # Fresh cohort: the pks are just the sks' public keys in supplied order.
    pks = [sk.public_key() for sk in sks]
    return mgr.CohortSpec(
        pks=pks, threshold=len(sks), sks=[(i, sk) for i, sk in enumerate(sks)]
    )


# --------------------------------------------------------------------------- #
# manager-keygen + cohort-keygen                                              #
# --------------------------------------------------------------------------- #


def cmd_manager_keygen(args):
    """1-of-1 cohort: generate a single Ed25519 keypair."""
    sk = ed25519.Ed25519PrivateKey.generate()
    save_publisher_sk(args.sk_out, sk)
    save_publisher_pk(args.pk_out, sk.public_key())
    print(f"cohort sk:  {args.sk_out}")
    print(f"cohort pk:  {args.pk_out}")


def cmd_cohort_keygen(args):
    """N-of-M cohort: generate N Ed25519 keypairs, write sk + pk for each."""
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for i in range(args.size):
        sk = ed25519.Ed25519PrivateKey.generate()
        save_publisher_sk(out_dir / f"cohort-{i}-sk.pem", sk)
        save_publisher_pk(out_dir / f"cohort-{i}-pk.pem", sk.public_key())
    print(f"wrote {args.size} cohort keypairs to {out_dir}/")
    print(f"threshold: {args.threshold}-of-{args.size}")


def cmd_witness_keygen(args):
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for i in range(args.size):
        sk = ed25519.Ed25519PrivateKey.generate()
        save_publisher_sk(out_dir / f"witness-{i}-sk.pem", sk)
        save_publisher_pk(out_dir / f"witness-{i}-pk.pem", sk.public_key())
    print(f"wrote {args.size} witness keypairs to {out_dir}/")


# --------------------------------------------------------------------------- #
# setup                                                                       #
# --------------------------------------------------------------------------- #


def cmd_setup(args):
    """Single-manager setup (1-of-1 cohort, no witnesses)."""
    spec = _build_cohort_spec([args.sk])
    setup = mgr.setup_election(
        log_path=args.log,
        cohort=spec,
        title=args.title,
        description=args.description,
        options=args.options.split(","),
        registration_close=args.registration_close,
        voting_open=args.voting_open,
        voting_close=args.voting_close,
    )
    print(f"election_id: {setup.election_id}")


def cmd_setup_cohort(args):
    """Threshold setup: 1+ cohort sk PEMs + optional witness pks."""
    sk_paths = [Path(p) for p in args.cohort_sks.split(",")]
    spec = _build_cohort_spec(sk_paths)
    if args.threshold:
        spec = mgr.CohortSpec(
            pks=spec.pks, threshold=args.threshold, sks=spec.sks[: args.threshold]
        )
    witness_pks: List[ed25519.Ed25519PublicKey] = []
    if args.witness_pks:
        for p in args.witness_pks.split(","):
            witness_pks.append(load_publisher_pk(Path(p)))
    setup = mgr.setup_election(
        log_path=args.log,
        cohort=spec,
        title=args.title,
        description=args.description,
        options=args.options.split(","),
        registration_close=args.registration_close,
        voting_open=args.voting_open,
        voting_close=args.voting_close,
        witness_pks=witness_pks,
        witness_threshold=args.witness_threshold,
    )
    print(f"election_id: {setup.election_id}")
    print(f"cohort: {spec.threshold}-of-{len(spec.pks)}")
    if witness_pks:
        print(f"witnesses: {args.witness_threshold}-of-{len(witness_pks)}")


# --------------------------------------------------------------------------- #
# Voter ops                                                                   #
# --------------------------------------------------------------------------- #


def cmd_voter_keygen(args):
    kp = vt.new_keypair()
    sk_b64, pk_b64 = vt.export_keypair(kp)
    args.out.write_text(json.dumps({"sk_b64": sk_b64, "pk_b64": pk_b64}, indent=2))
    print(f"voter key: {args.out}")
    print(f"voter pk:  {pk_b64}")


def cmd_register(args):
    sk_paths = [Path(p) for p in args.cohort_sks.split(",")] if args.cohort_sks else [args.sk]
    spec = _build_cohort_spec(sk_paths, args.log)
    voter_pk_raw = b64decode(args.voter_pk)
    reg = mgr.register_voter(
        log_path=args.log, cohort=spec,
        voter_pk=voter_pk_raw, voter_handle=args.handle,
    )
    print(f"registered: {args.handle} -> {reg.voter_pk_b64}")


def cmd_publish_ring(args):
    sk_paths = [Path(p) for p in args.cohort_sks.split(",")] if args.cohort_sks else [args.sk]
    spec = _build_cohort_spec(sk_paths, args.log)
    ring = mgr.publish_ring(log_path=args.log, cohort=spec)
    print(f"ring published with {len(ring.ring_b64)} voters")


def cmd_vote(args):
    obj = json.loads(args.voter_key.read_text())
    kp = vt.import_keypair(obj["sk_b64"], obj["pk_b64"])
    ctx = vt.load_voting_context(args.log)
    ballot = vt.cast_ballot(voter=kp, context=ctx, choice=args.choice)
    if args.manager_sk:
        sk_paths = [Path(p) for p in args.cohort_sks.split(",")] if args.cohort_sks else [args.manager_sk]
        spec = _build_cohort_spec(sk_paths, args.log)
        mgr.publish_ballot(log_path=args.log, cohort=spec, ballot=ballot)
        print(f"ballot submitted for choice={args.choice!r}")
    else:
        sys.stdout.write(json.dumps({
            "choice": ballot.choice, "otrs_sig_b64": ballot.otrs_sig_b64,
        }) + "\n")


def cmd_close(args):
    sk_paths = [Path(p) for p in args.cohort_sks.split(",")] if args.cohort_sks else [args.sk]
    spec = _build_cohort_spec(sk_paths, args.log)
    mgr.close_voting(log_path=args.log, cohort=spec)
    print("voting closed")


def cmd_tally(args):
    report = auditor_mod.audit(log_path=args.log)
    for opt in sorted(report.tally):
        print(f"  {opt:15s} {report.tally[opt]}")
    if report.double_sign_culprits:
        print(f"double-sign culprits: {len(report.double_sign_culprits)}")
    if args.publish:
        sk_paths = [Path(p) for p in args.cohort_sks.split(",")] if args.cohort_sks else ([args.sk] if args.sk else None)
        if sk_paths is None:
            _err("--publish requires --sk or --cohort-sks")
        spec = _build_cohort_spec(sk_paths, args.log)
        mgr.publish_tally(log_path=args.log, cohort=spec,
                          tally=auditor_mod.build_tally_record(report))
        print("tally published on log")


# --------------------------------------------------------------------------- #
# Async cohort co-signing                                                     #
# --------------------------------------------------------------------------- #


def cmd_propose(args):
    propose_entry(args.log, args.payload.encode())
    print(f"proposed pending entry at {args.log}.pending")


def cmd_sign_pending(args):
    spec = _build_cohort_spec([args.sk], args.log)
    # The cohort member's index in the cohort:
    member_pk_raw = pk_raw(load_publisher_sk(args.sk).public_key())
    pub = spec.as_publisher_cohort()
    idx = next(
        (i for i, pk in enumerate(pub.pks) if pk_raw(pk) == member_pk_raw),
        None,
    )
    if idx is None:
        _err("this --sk is not a cohort member")
    cosign_pending(args.log, idx, load_publisher_sk(args.sk), pub)
    print(f"added signature from cohort member {idx}")


def cmd_commit_pending(args):
    pub = _load_cohort_from_setup(args.log)
    entry = commit_pending(args.log, pub)
    print(f"committed entry at index {entry.index}")


# --------------------------------------------------------------------------- #
# Witness                                                                     #
# --------------------------------------------------------------------------- #


def cmd_witness_checkpoint(args):
    pub = _load_cohort_from_setup(args.log)
    sk = load_publisher_sk(args.sk)
    cp = wit.emit_checkpoint(
        log_path=args.log, cohort=pub, witness_sk=sk,
        witness_index=args.witness_index,
    )
    print(f"witness {args.witness_index} checkpoint: idx={cp.log_index}")


# --------------------------------------------------------------------------- #
# audit + show                                                                #
# --------------------------------------------------------------------------- #


def cmd_audit(args):
    try:
        report = auditor_mod.audit(log_path=args.log)
    except auditor_mod.AuditError as e:
        _err(f"AUDIT FAILED: {e}")
    print(f"election:               {report.setup.title}")
    print(f"election_id:            {report.setup.election_id}")
    print(f"cohort:                 {report.setup.threshold}-of-{len(report.setup.cohort_pks_b64)}")
    if report.setup.witness_pks_b64:
        print(f"witnesses:              {report.setup.witness_threshold}"
              f"-of-{len(report.setup.witness_pks_b64)}; "
              f"valid checkpoints: {report.witness_count}; "
              f"latest co-signed idx: {report.witness_cosigned_index}")
    print(f"ring size:              {len(report.ring)}")
    print(f"accepted ballots:       {len(report.accepted_ballot_indices)}")
    print(f"rejected ballots:       {len(report.rejected_ballot_indices)}")
    print("tally:")
    for opt in sorted(report.tally):
        print(f"  {opt:15s} {report.tally[opt]}")
    print(f"double-sign culprits:   {len(report.double_sign_culprits)}")
    if report.claimed_tally is not None:
        ok = report.tally_matches_claim()
        print(f"manager-claimed tally matches: {ok}")
        if not ok:
            sys.exit(2)


def cmd_show(args):
    log = BulletinBoard(args.log)
    for entry in log.read_all():
        try:
            rec = parse_payload(entry.payload)
            kind = type(rec).__name__
        except Exception:
            kind = "<unparseable>"
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(entry.timestamp))
        sigs = len(entry.publisher_sigs)
        print(f"#{entry.index:3d} {ts} {kind:25s} (cohort sigs: {sigs})")


# --------------------------------------------------------------------------- #
# Parser                                                                      #
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="evote")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_cohort_arg(sp, required: bool = False) -> None:
        sp.add_argument(
            "--cohort-sks", default=None,
            help="comma-separated cohort sk PEM paths (threshold mode)",
        )

    s = sub.add_parser("manager-keygen", help="1-of-1 cohort: generate one keypair")
    s.add_argument("--sk-out", type=Path, required=True)
    s.add_argument("--pk-out", type=Path, required=True)
    s.set_defaults(func=cmd_manager_keygen)

    s = sub.add_parser("cohort-keygen", help="N-of-M cohort: generate N keypairs")
    s.add_argument("--size", type=int, required=True, help="cohort size N")
    s.add_argument("--threshold", type=int, required=True, help="threshold t (≤ N)")
    s.add_argument("--out-dir", type=Path, required=True)
    s.set_defaults(func=cmd_cohort_keygen)

    s = sub.add_parser("witness-keygen", help="Generate M witness keypairs")
    s.add_argument("--size", type=int, required=True)
    s.add_argument("--out-dir", type=Path, required=True)
    s.set_defaults(func=cmd_witness_keygen)

    s = sub.add_parser("setup", help="Setup with a single-manager cohort (1-of-1)")
    s.add_argument("--log", type=Path, required=True)
    s.add_argument("--sk", type=Path, required=True)
    s.add_argument("--title", required=True)
    s.add_argument("--description", default="")
    s.add_argument("--options", required=True, help="comma-separated")
    s.add_argument("--registration-close", type=int, required=True)
    s.add_argument("--voting-open", type=int, required=True)
    s.add_argument("--voting-close", type=int, required=True)
    s.set_defaults(func=cmd_setup)

    s = sub.add_parser("setup-cohort", help="Setup with a t-of-N cohort + witnesses")
    s.add_argument("--log", type=Path, required=True)
    s.add_argument("--cohort-sks", required=True,
                   help="comma-separated cohort sk PEM paths")
    s.add_argument("--threshold", type=int, default=None,
                   help="threshold t; defaults to len(cohort-sks)")
    s.add_argument("--witness-pks", default=None,
                   help="comma-separated witness pk PEM paths (optional)")
    s.add_argument("--witness-threshold", type=int, default=0)
    s.add_argument("--title", required=True)
    s.add_argument("--description", default="")
    s.add_argument("--options", required=True)
    s.add_argument("--registration-close", type=int, required=True)
    s.add_argument("--voting-open", type=int, required=True)
    s.add_argument("--voting-close", type=int, required=True)
    s.set_defaults(func=cmd_setup_cohort)

    s = sub.add_parser("voter-keygen", help="Generate voter OTRS keypair")
    s.add_argument("--out", type=Path, required=True)
    s.set_defaults(func=cmd_voter_keygen)

    s = sub.add_parser("register", help="Cohort attests + publishes a voter pk")
    s.add_argument("--log", type=Path, required=True)
    s.add_argument("--sk", type=Path, default=None)
    s.add_argument("--cohort-sks", default=None)
    s.add_argument("--voter-pk", required=True)
    s.add_argument("--handle", required=True)
    s.set_defaults(func=cmd_register)

    s = sub.add_parser("publish-ring", help="Close registration, open voting")
    s.add_argument("--log", type=Path, required=True)
    s.add_argument("--sk", type=Path, default=None)
    s.add_argument("--cohort-sks", default=None)
    s.set_defaults(func=cmd_publish_ring)

    s = sub.add_parser("vote", help="Cast a ballot")
    s.add_argument("--log", type=Path, required=True)
    s.add_argument("--voter-key", type=Path, required=True)
    s.add_argument("--choice", required=True)
    s.add_argument("--manager-sk", type=Path, default=None)
    s.add_argument("--cohort-sks", default=None)
    s.set_defaults(func=cmd_vote)

    s = sub.add_parser("close", help="Close voting")
    s.add_argument("--log", type=Path, required=True)
    s.add_argument("--sk", type=Path, default=None)
    s.add_argument("--cohort-sks", default=None)
    s.set_defaults(func=cmd_close)

    s = sub.add_parser("tally", help="Recompute the tally (optionally publish)")
    s.add_argument("--log", type=Path, required=True)
    s.add_argument("--publish", action="store_true")
    s.add_argument("--sk", type=Path, default=None)
    s.add_argument("--cohort-sks", default=None)
    s.set_defaults(func=cmd_tally)

    s = sub.add_parser("propose", help="Create a pending entry (async cohort flow)")
    s.add_argument("--log", type=Path, required=True)
    s.add_argument("--payload", required=True, help="raw bytes to commit")
    s.set_defaults(func=cmd_propose)

    s = sub.add_parser("sign-pending", help="Co-sign the pending entry")
    s.add_argument("--log", type=Path, required=True)
    s.add_argument("--sk", type=Path, required=True)
    s.set_defaults(func=cmd_sign_pending)

    s = sub.add_parser("commit-pending", help="Commit the pending entry once threshold met")
    s.add_argument("--log", type=Path, required=True)
    s.set_defaults(func=cmd_commit_pending)

    s = sub.add_parser("witness-checkpoint", help="Witness emits a co-sign of the log head")
    s.add_argument("--log", type=Path, required=True)
    s.add_argument("--sk", type=Path, required=True)
    s.add_argument("--witness-index", type=int, required=True)
    s.set_defaults(func=cmd_witness_checkpoint)

    s = sub.add_parser("audit", help="Verify the log and print the canonical result")
    s.add_argument("--log", type=Path, required=True)
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("show", help="Pretty-print the log entries")
    s.add_argument("--log", type=Path, required=True)
    s.set_defaults(func=cmd_show)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

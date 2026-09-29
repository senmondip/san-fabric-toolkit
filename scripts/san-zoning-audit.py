#!/usr/bin/env python3
"""
san-zoning-audit - Brocade/Cisco SAN zoning audit

WHAT IT DOES
  Collects (over SSH) or reads (from saved files) a fabric's zoning database and
  name-server table, then reports:
    ERROR    multi_initiator          zone has 2+ initiators (single-initiator violation)
    WARNING  orphan_zone              zone is not a member of any cfg / zoneset
    WARNING  active_zone_not_defined  zone is enforced now but missing from the defined DB
    WARNING  unresolved_reference     cfg/zone references a zone/alias that does not exist
    WARNING  empty_zone               zone has no members
    WARNING  no_active_config         no effective cfg / active zoneset
    WARNING  unverified_roles         zones whose single-initiator status cannot be proven
    WARNING  full_db_fallback         (Cisco) full zone DB empty, audited the active DB instead
    INFO     inactive_zone            zone only appears in non-active cfgs/zonesets
    INFO     orphan_alias             alias / fcalias not used by any zone
    INFO     stale_member             zoned WWN is not logged in to the fabric
    INFO     multi_initiator_exempt   multiple initiators, but peer zone / smart zoning

COMMANDS USED (read-only; nothing is changed on the switch)
  Brocade FOS : cfgshow, nsshow, nscamshow
                (with --fid: fosexec --fid N -cmd "<cmd>")
  Cisco MDS   : show running-config, show fcns database

OPERATIONAL ASSUMPTIONS
  * SSH access uses the system OpenSSH client. The switch host key must already be
    in known_hosts. This script does not turn off host-key checking. If you need to,
    use --ssh-option.
  * Auth: key-based by default (BatchMode, so a missing key fails instead of hanging).
    For password auth, put the password in $SAN_PASSWORD (or the variable named by
    --password-env) and install `sshpass`. Passwords are never accepted on the
    command line, so they don't end up in `ps` output or shell history.
  * The account needs read access to zoning and the name server (the Brocade "user"
    role and the Cisco "network-operator" role are both enough).
  * Brocade: zoning is fabric-wide, so any switch in the fabric works. nsshow shows
    only local devices and nscamshow shows remote ones. Both are collected.
    "Device type:" lines in nsshow (FOS 7.x+) are used to tell initiators from targets.
  * Cisco: `show running-config` has the zone DB. On switches that have only the
    ACTIVE DB (the default "zoneset distribute active"), the full DB can be empty. In
    that case this script audits the active DB and flags it. Run the audit on the
    switch where zoning is administered.
  * An initiator or target is identified by, in order of precedence:
      1. Cisco smart-zoning member tag (init/target/both)
      2. name-server FC4 role (Brocade "Device type", Cisco "scsi-fcp:init/target")
      3. --initiator-regex / --target-regex matched against alias names
    WWN-prefix/OUI guessing is deliberately NOT used. Vendors reuse prefixes for both
    HBAs and array ports, so a guess would produce false positives and false negatives.
  * Brocade peer zones (property member 00:02:00:00:00:0x:..) and Cisco smart-zoned
    VSANs are allowed to contain multiple initiators. They are reported as INFO.
  * Port-based members (Brocade "D,I", Cisco interface/fcid/domain-id) cannot be
    mapped to a role. They count as unknown.

HOW TO RUN
  Live, key auth:
    san-zoning-audit.py --platform brocade --host "$SAN_HOST" --user "$SAN_USER"
  Live, password auth (needs sshpass):
    read -rs SAN_PASSWORD && export SAN_PASSWORD
    san-zoning-audit.py --platform cisco --host mds01 --user auditor --vsan 10 --json
  Offline, from captured output:
    san-zoning-audit.py --platform brocade --zoning-file cfgshow.txt \
        --nameserver-file nsshow.txt --nameserver-file nscamshow.txt

  Environment defaults: SAN_HOST, SAN_USER, SAN_SSH_PORT, SAN_SSH_KEY, SAN_PASSWORD,
  SAN_INITIATOR_REGEX, SAN_TARGET_REGEX.

EXIT CODES
  0  no ERROR findings (and no WARNING findings when --strict is used)
  1  findings at or above the failure threshold
  2  operational failure (bad arguments, SSH/auth failure, unparseable output)
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

VERSION = "1.0.0"

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_FAILURE = 2

SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}

WWN_ANY = r"(?:[0-9a-fA-F]{2}:){7}[0-9a-fA-F]{2}"
WWN_RE = re.compile(r"^" + WWN_ANY + r"$")
BROCADE_DI_RE = re.compile(r"^\d+,\d+$")
# Brocade peer zones carry a synthetic "property member" as their first entry,
# formatted as 00:02:00:00:00:0X:NN:NN. It is not a device.
BROCADE_PEER_PROPERTY_RE = re.compile(r"^00:02:00:00:00:0[0-9a-f]:", re.I)

# Text that means the switch rejected the command rather than returning data.
# All of these contain spaces, so they cannot collide with zone/alias names.
CLI_ERROR_PATTERNS = [
    re.compile(p, re.I)
    for p in (
        r"^% ?Invalid (command|input)",
        r"Syntax error",
        r"command not found",
        r"RBAC permission denied",
        r"Permission denied",
        r"not permitted",
        r"Invalid FID",
    )
]

REMEDIATION = {
    "multi_initiator": (
        "Split into one zone per initiator (single-initiator, single- or multi-target). "
        "If the grouping is intentional, convert it to a peer zone (Brocade) or enable "
        "smart zoning for the VSAN (Cisco)."
    ),
    "orphan_zone": (
        "The zone is not in any cfg/zoneset and has no effect. Confirm it is not staged "
        "for a pending change, then delete it (Brocade: zonedelete + cfgsave; "
        "Cisco: no zone name <z> vsan <n>, then zone commit if in enhanced mode)."
    ),
    "active_zone_not_defined": (
        "The zone is enforced now but missing from the defined database. The next "
        "cfgenable / zoneset activate will remove it. Recreate it, or confirm removal is intended."
    ),
    "unresolved_reference": (
        "Fix or remove the dangling reference. Missing objects are dropped or cause "
        "activation errors."
    ),
    "empty_zone": "Remove the zone or add its intended members.",
    "no_active_config": (
        "No effective cfg / active zoneset. Unless the default zone permits all access, "
        "no devices can communicate. Verify that this is intentional."
    ),
    "unverified_roles": (
        "Initiator/target roles for some members are unknown. Supply name-server data "
        "(live run, or --nameserver-file) or --initiator-regex/--target-regex."
    ),
    "full_db_fallback": (
        "The audit used the ACTIVE zone DB. Re-run it against the switch where zoning is "
        "administered, or distribute the full DB (zoneset distribute full vsan <n>)."
    ),
    "inactive_zone": "The zone appears only in non-active cfgs/zonesets. Confirm those cfgs are still needed.",
    "orphan_alias": "No zone uses this alias. Remove it if the device is decommissioned.",
    "stale_member": (
        "The WWN is not logged in to the fabric. If the device is decommissioned, remove "
        "it from zones and aliases. If it should be online, check cabling/HBA."
    ),
    "multi_initiator_exempt": (
        "No action needed. Peer/smart zoning blocks initiator-to-initiator traffic."
    ),
}

Key = Tuple[Optional[int], str]  # (vsan or None for Brocade, object name)


class AuditError(Exception):
    """A failure that should stop the run with a clear message (exit 2)."""


# --------------------------------------------------------------------------- model


@dataclass
class Member:
    kind: str  # "wwn" | "alias" | "device-alias" | "other"
    value: str
    tag: Optional[str] = None  # Cisco smart-zoning role tag, already normalised


@dataclass
class Zone:
    name: str
    vsan: Optional[int]
    members: List[Member] = field(default_factory=list)
    peer: bool = False
    smart_disabled: bool = False


@dataclass
class ZoneDB:
    platform: str
    zones: Dict[Key, Zone] = field(default_factory=dict)
    aliases: Dict[Key, List[Member]] = field(default_factory=dict)
    device_aliases: Dict[str, str] = field(default_factory=dict)  # Cisco only
    configs: Dict[Key, List[str]] = field(default_factory=dict)
    active_config_names: List[str] = field(default_factory=list)
    active_zones: Set[Key] = field(default_factory=set)
    active_vsans: Set[Optional[int]] = field(default_factory=set)
    smart_vsans: Set[int] = field(default_factory=set)
    fallback_vsans: Set[int] = field(default_factory=set)


@dataclass
class NameServer:
    roles: Dict[str, str] = field(default_factory=dict)
    present: Set[str] = field(default_factory=set)


@dataclass
class Endpoint:
    ident: str
    is_wwn: bool
    labels: List[str] = field(default_factory=list)
    tag: Optional[str] = None
    role: str = "unknown"
    role_source: Optional[str] = None


@dataclass
class Finding:
    severity: str
    category: str
    obj: str
    message: str
    details: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "object": self.obj,
            "message": self.message,
            "remediation": REMEDIATION.get(self.category, ""),
            "details": self.details,
        }


def norm_wwn(text: str) -> str:
    return text.strip().lower()


def display_key(key: Key) -> str:
    vsan, name = key
    return name if vsan is None else f"{name} [vsan {vsan}]"


def role_from_text(text: str) -> str:
    """Map name-server role text to initiator/target/both/unknown."""
    t = text.lower()
    # Brocade prints "Physical Unknown(initiator/target)" when it cannot tell, so
    # look for "unknown" first.
    if "unknown" in t:
        return "unknown"
    is_init = "initiator" in t or re.search(r"\binit\b", t) is not None
    is_tgt = "target" in t
    if "both" in t or (is_init and is_tgt):
        return "both"
    if is_init:
        return "initiator"
    if is_tgt:
        return "target"
    return "unknown"


def merge_role(old: Optional[str], new: str) -> str:
    if not old or old == "unknown":
        return new
    if new == "unknown" or new == old:
        return old
    return "both"


# ------------------------------------------------------------------ Brocade parse

BROCADE_OBJ_RE = re.compile(r"^\s*(cfg|zone|alias):\s*(\S+)\s*(.*)$")


def _split_brocade_members(text: str) -> List[str]:
    return [t for t in re.split(r"[;\s]+", text) if t]


def _brocade_member(token: str) -> Member:
    if WWN_RE.match(token):
        return Member("wwn", norm_wwn(token))
    if BROCADE_DI_RE.match(token):
        return Member("other", token)
    return Member("alias", token)


def parse_brocade_cfgshow(text: str) -> ZoneDB:
    if not re.search(r"^\s*Defined configuration", text, re.M | re.I):
        raise AuditError(
            "Zoning output does not look like Brocade 'cfgshow' output "
            "('Defined configuration:' header not found)."
        )
    db = ZoneDB("brocade")
    raw: Dict[Tuple[str, str], List[str]] = {}
    section: Optional[str] = None
    current: Optional[Tuple[str, str]] = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        low = stripped.lower()
        if low.startswith("defined configuration"):
            section, current = "defined", None
            continue
        if low.startswith("effective configuration"):
            section, current = "effective", None
            continue
        if section is None:
            continue

        m = BROCADE_OBJ_RE.match(line)
        if m:
            kind, name, rest = m.groups()
            if section == "defined":
                current = (kind, name)
                raw.setdefault(current, []).extend(_split_brocade_members(rest))
            else:
                # The effective section lists zones with aliases already expanded to
                # WWNs. Only the names matter here: they are what the fabric enforces now.
                current = None
                if kind == "cfg":
                    db.active_config_names.append(name)
                elif kind == "zone":
                    db.active_zones.add((None, name))
            continue

        # Long member lists wrap onto indented continuation lines.
        if section == "defined" and current and line[:1].isspace():
            raw[current].extend(_split_brocade_members(stripped))

    for (kind, name), tokens in raw.items():
        key: Key = (None, name)
        if kind == "cfg":
            db.configs[key] = tokens
        elif kind == "zone":
            zone = Zone(name, None)
            for tok in tokens:
                if BROCADE_PEER_PROPERTY_RE.match(tok):
                    zone.peer = True
                    continue
                zone.members.append(_brocade_member(tok))
            db.zones[key] = zone
        elif kind == "alias":
            db.aliases[key] = [_brocade_member(t) for t in tokens]

    if db.active_config_names:
        db.active_vsans.add(None)
    return db


BROCADE_NS_ENTRY_RE = re.compile(
    r"^\s*(?:N|NL|U)\s+([0-9a-fA-F]{6});[^;]*;\s*(" + WWN_ANY + r");\s*(" + WWN_ANY + r");"
)
BROCADE_DEVTYPE_RE = re.compile(r"^\s*Device type:\s*(.+?)\s*$", re.I)


def parse_brocade_nameserver(text: str, ns: NameServer) -> int:
    """Parse nsshow / nscamshow output into ns. Returns number of entries found."""
    count = 0
    current: List[str] = []
    for line in text.splitlines():
        m = BROCADE_NS_ENTRY_RE.match(line)
        if m:
            count += 1
            pwwn, nwwn = norm_wwn(m.group(2)), norm_wwn(m.group(3))
            current = [pwwn, nwwn]
            # Node WWNs are recorded too, because FOS permits node-WWN zone members.
            ns.present.update(current)
            continue
        d = BROCADE_DEVTYPE_RE.match(line)
        if d and current:
            role = role_from_text(d.group(1))
            for w in current:
                ns.roles[w] = merge_role(ns.roles.get(w), role)
    return count


# -------------------------------------------------------------------- Cisco parse

CISCO_ZONE_HDR = re.compile(r"^zone name (\S+) vsan (\d+)\s*$")
CISCO_ZONESET_HDR = re.compile(r"^zoneset name (\S+) vsan (\d+)\s*$")
CISCO_FCALIAS_HDR = re.compile(r"^fcalias name (\S+) vsan (\d+)\s*$")
CISCO_ACTIVATE = re.compile(r"^zoneset activate name (\S+) vsan (\d+)")
CISCO_SMART = re.compile(r"^zone smart-zoning enable vsan (\d+)")
CISCO_DEVICE_ALIAS = re.compile(r"^\s*device-alias name (\S+) pwwn (" + WWN_ANY + r")")
CISCO_MEMBER = re.compile(r"^\s+member\s+(.+?)\s*$")
CISCO_SECTION = re.compile(r"^!(Active|Full) Zone Database Section for vsan (\d+)", re.I)
CISCO_SMART_TAGS = {"init": "initiator", "target": "target", "both": "both"}


def _cisco_member(text: str) -> Member:
    toks = text.split()
    kind = toks[0].lower()
    tag = None
    if len(toks) > 2 and toks[-1].lower() in CISCO_SMART_TAGS:
        tag = CISCO_SMART_TAGS[toks[-1].lower()]
    if kind == "pwwn" and len(toks) >= 2 and WWN_RE.match(toks[1]):
        return Member("wwn", norm_wwn(toks[1]), tag)
    if kind == "device-alias" and len(toks) >= 2:
        return Member("device-alias", toks[1], tag)
    if kind == "fcalias" and len(toks) >= 2:
        return Member("alias", toks[1], tag)
    # interface / fcid / fwwn / domain-id / ip-address / symbolic-nodename
    return Member("other", text, tag)


def parse_cisco_running_config(text: str) -> ZoneDB:
    if not re.search(r"^(version |vsan database|zone |zoneset |fcalias |device-alias )", text, re.M):
        raise AuditError(
            "Zoning output does not look like Cisco NX-OS 'show running-config' output."
        )
    db = ZoneDB("cisco")
    # NX-OS prints an "Active Zone Database Section" and a "Full Zone Database Section"
    # for each VSAN. Both define the same zone names. Definitions come from the full
    # section; the active section is kept separately for enforcement state and fallback.
    act_zones: Dict[Key, Zone] = {}
    act_aliases: Dict[Key, List[Member]] = {}
    act_sets: Dict[Key, List[str]] = {}
    activated: Set[Key] = set()
    section = "full"  # with no section markers, everything is treated as the full DB
    block: Optional[Tuple[str, Key]] = None

    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[:1].isspace():
            block = None
            m = CISCO_SECTION.match(line)
            if m:
                section = m.group(1).lower()
                continue
            m = CISCO_ZONE_HDR.match(line)
            if m:
                key = (int(m.group(2)), m.group(1))
                target = act_zones if section == "active" else db.zones
                target[key] = Zone(m.group(1), int(m.group(2)))
                block = ("zone_active" if section == "active" else "zone", key)
                continue
            m = CISCO_FCALIAS_HDR.match(line)
            if m:
                key = (int(m.group(2)), m.group(1))
                target_a = act_aliases if section == "active" else db.aliases
                target_a[key] = []
                block = ("fcalias_active" if section == "active" else "fcalias", key)
                continue
            m = CISCO_ZONESET_HDR.match(line)
            if m:
                key = (int(m.group(2)), m.group(1))
                if section == "active":
                    act_sets[key] = []
                    block = ("zoneset_active", key)
                else:
                    db.configs[key] = []
                    block = ("zoneset", key)
                continue
            m = CISCO_ACTIVATE.match(line)
            if m:
                activated.add((int(m.group(2)), m.group(1)))
                continue
            m = CISCO_SMART.match(line)
            if m:
                db.smart_vsans.add(int(m.group(1)))
            continue

        m = CISCO_DEVICE_ALIAS.match(line)
        if m:
            db.device_aliases[m.group(1)] = norm_wwn(m.group(2))
            continue
        if block is None:
            continue
        btype, key = block
        if btype in ("zone", "zone_active") and "disable-smart-zoning" in line:
            (db.zones if btype == "zone" else act_zones)[key].smart_disabled = True
            continue
        m = CISCO_MEMBER.match(line)
        if not m:
            continue
        body = m.group(1)
        if btype == "zone":
            db.zones[key].members.append(_cisco_member(body))
        elif btype == "zone_active":
            act_zones[key].members.append(_cisco_member(body))
        elif btype == "fcalias":
            db.aliases[key].append(_cisco_member(body))
        elif btype == "fcalias_active":
            act_aliases[key].append(_cisco_member(body))
        elif btype == "zoneset":
            db.configs[key].append(body.split()[0])
        elif btype == "zoneset_active":
            act_sets[key].append(body.split()[0])

    # Fallback: if a VSAN has an active DB but an empty full DB, the full DB was
    # probably never distributed to this switch.
    full_vsans = {k[0] for k in db.zones} | {k[0] for k in db.configs}
    for key, zone in act_zones.items():
        if key[0] not in full_vsans:
            db.zones[key] = zone
            db.fallback_vsans.add(key[0])
    for key, members in act_aliases.items():
        if key[0] in db.fallback_vsans:
            db.aliases.setdefault(key, members)
    for key, zones in act_sets.items():
        if key[0] in db.fallback_vsans:
            db.configs.setdefault(key, zones)

    for key in sorted(activated, key=lambda k: (k[0] or 0, k[1])):
        members = act_sets.get(key, db.configs.get(key, []))
        db.active_zones.update((key[0], z) for z in members)
        db.active_vsans.add(key[0])
        db.active_config_names.append(display_key(key))
    return db


CISCO_FCNS_ROW = re.compile(r"^\s*(0x[0-9a-fA-F]{6})\s+\S+\s+(" + WWN_ANY + r")(.*)$")


def parse_cisco_fcns(text: str, ns: NameServer) -> int:
    """Parse 'show fcns database' (tabular form). Returns number of entries found."""
    count = 0
    last: Optional[str] = None
    remainders: Dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            last = None
            continue
        m = CISCO_FCNS_ROW.match(line)
        if m:
            count += 1
            last = norm_wwn(m.group(2))
            ns.present.add(last)
            remainders[last] = remainders.get(last, "") + " " + m.group(3)
            continue
        s = line.strip()
        # A wide FC4-TYPE:FEATURE column wraps onto an indented line with no FCID.
        if last and line[:1].isspace() and not s.startswith(("-", "VSAN", "FCID", "Total")):
            remainders[last] += " " + s
    for wwn, rest in remainders.items():
        rest = re.sub(r"\([^)]*\)", " ", rest)  # drop "(Vendor)" so its text is not read as a role
        ns.roles[wwn] = merge_role(ns.roles.get(wwn), role_from_text(rest))
    return count


# ---------------------------------------------------------------------- collection

COMMANDS = {
    "brocade": {
        "zoning": "cfgshow",
        # (command, required). nscamshow may have nothing to report on a
        # single-switch fabric, so its failure is not fatal.
        "nameserver": [("nsshow", True), ("nscamshow", False)],
    },
    "cisco": {
        "zoning": "show running-config",
        "nameserver": [("show fcns database", True)],
    },
}


def check_cli_errors(text: str, command: str) -> None:
    # The switch reports rejected commands at the top of the output, so only the
    # first few lines are checked.
    for line in text.splitlines()[:5]:
        for pat in CLI_ERROR_PATTERNS:
            if pat.search(line.strip()):
                raise AuditError(f"Switch rejected '{command}': {line.strip()}")


class SSHRunner:
    def __init__(self, args: argparse.Namespace, host: str, user: str):
        self.args = args
        self.host = host
        self.user = user
        ssh = shutil.which("ssh")
        if not ssh:
            raise AuditError("OpenSSH client 'ssh' not found in PATH.")
        self.env = os.environ.copy()
        base = [
            ssh, "-p", str(args.port),
            "-o", f"ConnectTimeout={args.connect_timeout}",
            "-o", "ServerAliveInterval=15",
        ]
        password = os.environ.get(args.password_env)
        if password:
            sshpass = shutil.which("sshpass")
            if not sshpass:
                raise AuditError(
                    f"${args.password_env} is set, but 'sshpass' is not installed. Install "
                    f"sshpass or unset ${args.password_env} to use key-based auth."
                )
            # sshpass -e reads $SSHPASS, which keeps the password out of argv.
            self.env["SSHPASS"] = password
            base = [sshpass, "-e"] + base + [
                "-o", "BatchMode=no",
                "-o", "PubkeyAuthentication=no",
                "-o", "PreferredAuthentications=password,keyboard-interactive",
            ]
            self.password_auth = True
        else:
            # BatchMode makes a missing/unauthorised key fail at once instead of
            # waiting at a password prompt.
            base += ["-o", "BatchMode=yes"]
            self.password_auth = False
        if args.identity:
            if not Path(args.identity).is_file():
                raise AuditError(f"SSH identity file not found: {args.identity}")
            base += ["-i", args.identity]
        for opt in args.ssh_option:
            base += ["-o", opt]
        self.base = base + ["-l", user, host]

    def wrap(self, command: str) -> str:
        if self.args.fid is not None:
            # With Virtual Fabrics, each logical switch has its own zoning DB.
            return f'fosexec --fid {self.args.fid} -cmd "{command}"'
        return command

    def run(self, command: str, required: bool = True) -> Optional[str]:
        remote = self.wrap(command)
        try:
            proc = subprocess.run(
                self.base + [remote], env=self.env, capture_output=True,
                text=True, errors="replace", timeout=self.args.timeout,
            )
        except subprocess.TimeoutExpired:
            raise AuditError(f"'{remote}' on {self.host} timed out after {self.args.timeout}s.")
        out = proc.stdout.replace("\r", "")
        err = proc.stderr.strip()
        if self.password_auth and proc.returncode == 5:
            raise AuditError(f"Password rejected for {self.user}@{self.host}.")
        if self.password_auth and proc.returncode == 6:
            raise AuditError(
                f"Host key for {self.host} is not in known_hosts. Verify it and add it first "
                "(e.g. ssh-keyscan, then check the fingerprint)."
            )
        if proc.returncode == 255:
            raise AuditError(f"SSH to {self.user}@{self.host} failed: {err or 'no detail'}")
        if proc.returncode != 0:
            if not out.strip():
                msg = f"'{remote}' failed on {self.host} (rc={proc.returncode}): {err or 'no output'}"
                if required:
                    raise AuditError(msg)
                print(f"san-zoning-audit: warning: {msg}", file=sys.stderr)
                return None
            # Some FOS/NX-OS builds return non-zero with valid output. Keep the output,
            # and let the parser sanity checks decide whether it is usable.
            print(f"san-zoning-audit: note: '{remote}' returned rc={proc.returncode}; "
                  "output will be validated.", file=sys.stderr)
        check_cli_errors(out, remote)
        return out


def read_file(path: str) -> str:
    p = Path(path)
    if not p.is_file():
        raise AuditError(f"File not found: {path}")
    return p.read_text(encoding="utf-8", errors="replace").replace("\r", "")


def save_raw(directory: str, platform: str, label: str, text: str) -> None:
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", label)
    (d / f"{platform}_{safe}_{stamp}.txt").write_text(text, encoding="utf-8")


# ------------------------------------------------------------------------- audit


def resolve(db: ZoneDB, vsan: Optional[int], m: Member, missing: List[str],
            depth: int = 0) -> List[Endpoint]:
    if m.kind == "wwn":
        return [Endpoint(m.value, True, [], m.tag)]
    if m.kind == "device-alias":
        wwn = db.device_aliases.get(m.value)
        if wwn is None:
            missing.append(f"device-alias {m.value}")
            return []
        return [Endpoint(wwn, True, [m.value], m.tag)]
    if m.kind == "alias":
        members = db.aliases.get((vsan, m.value))
        if members is None:
            missing.append(f"alias {m.value}")
            return []
        out: List[Endpoint] = []
        if depth > 2:  # neither platform nests aliases this deep; guard against loops
            return out
        for am in members:
            for ep in resolve(db, vsan, am, missing, depth + 1):
                ep.labels.insert(0, m.value)
                ep.tag = ep.tag or m.tag
                out.append(ep)
        return out
    return [Endpoint(m.value, False, [], m.tag)]


def classify(ep: Endpoint, ns: Optional[NameServer],
             init_re: Optional[re.Pattern], tgt_re: Optional[re.Pattern]) -> None:
    if ep.tag:
        ep.role, ep.role_source = ep.tag, "smart-zoning tag"
        return
    if ep.is_wwn and ns and ns.roles.get(ep.ident, "unknown") != "unknown":
        ep.role, ep.role_source = ns.roles[ep.ident], "name server"
        return
    for label in ep.labels:
        if init_re and init_re.search(label):
            ep.role, ep.role_source = "initiator", "name pattern"
            return
        if tgt_re and tgt_re.search(label):
            ep.role, ep.role_source = "target", "name pattern"
            return


def ep_text(ep: Endpoint) -> str:
    return f"{'/'.join(ep.labels)} ({ep.ident})" if ep.labels else ep.ident


def ep_dict(ep: Endpoint) -> dict:
    return {"id": ep.ident, "aliases": ep.labels, "role": ep.role, "role_source": ep.role_source}


def audit(db: ZoneDB, ns: Optional[NameServer], init_re, tgt_re,
          vsans: Set[int]) -> Tuple[List[Finding], dict]:
    def in_scope(key: Key) -> bool:
        return not vsans or key[0] in vsans

    zones = {k: z for k, z in db.zones.items() if in_scope(k)}
    configs = {k: v for k, v in db.configs.items() if in_scope(k)}
    aliases = {k: v for k, v in db.aliases.items() if in_scope(k)}
    findings: List[Finding] = []

    referenced_zones: Set[Key] = set()
    for ckey, znames in configs.items():
        for zname in znames:
            zkey = (ckey[0], zname)
            referenced_zones.add(zkey)
            if zkey not in db.zones:
                findings.append(Finding(
                    "warning", "unresolved_reference", display_key(ckey),
                    f"config references undefined zone '{zname}'", {"missing": zname}))

    referenced_aliases: Set[Key] = set()
    unverified: List[str] = []
    ns_usable = bool(ns and ns.present)

    for key in sorted(zones, key=lambda k: (k[0] or 0, k[1])):
        zone = zones[key]
        name = display_key(key)
        if not zone.members:
            findings.append(Finding("warning", "empty_zone", name, "zone has no members"))

        missing: List[str] = []
        merged: Dict[str, Endpoint] = {}
        for m in zone.members:
            if m.kind == "alias":
                referenced_aliases.add((zone.vsan, m.value))
            for ep in resolve(db, zone.vsan, m, missing):
                if ep.ident in merged:
                    prev = merged[ep.ident]
                    prev.labels += [lbl for lbl in ep.labels if lbl not in prev.labels]
                    prev.tag = prev.tag or ep.tag
                else:
                    merged[ep.ident] = ep
        if missing:
            findings.append(Finding(
                "warning", "unresolved_reference", name,
                "zone references undefined object(s): " + ", ".join(missing),
                {"missing": missing}))

        eps = list(merged.values())
        for ep in eps:
            classify(ep, ns, init_re, tgt_re)
        inits = [e for e in eps if e.role == "initiator"]
        unknown = [e for e in eps if e.role == "unknown"]
        details = {"members": [ep_dict(e) for e in eps]}

        if len(inits) >= 2:
            smart = zone.vsan is not None and zone.vsan in db.smart_vsans and not zone.smart_disabled
            if zone.peer or smart:
                findings.append(Finding(
                    "info", "multi_initiator_exempt", name,
                    f"{len(inits)} initiators, allowed by {'peer zoning' if zone.peer else 'smart zoning'}",
                    details))
            else:
                findings.append(Finding(
                    "error", "multi_initiator", name,
                    f"{len(inits)} initiators: " + ", ".join(ep_text(e) for e in inits),
                    details))
        elif unknown and len(inits) + len(unknown) >= 2:
            # Kept as one summary finding (below). Offline runs would otherwise
            # emit a warning for nearly every zone.
            unverified.append(name)

        if ns_usable:
            stale = [e for e in eps if e.is_wwn and e.ident not in ns.present]
            if stale:
                findings.append(Finding(
                    "info", "stale_member", name,
                    "not logged in: " + ", ".join(ep_text(e) for e in stale),
                    {"stale": [ep_dict(e) for e in stale]}))

        if key not in referenced_zones:
            findings.append(Finding("warning", "orphan_zone", name,
                                    "zone is not a member of any config/zoneset"))
        elif zone.vsan in db.active_vsans and key not in db.active_zones:
            findings.append(Finding("info", "inactive_zone", name,
                                    "zone appears only in non-active configs"))

    for key in sorted(db.active_zones, key=lambda k: (k[0] or 0, k[1])):
        if in_scope(key) and key not in db.zones:
            findings.append(Finding(
                "warning", "active_zone_not_defined", display_key(key),
                "zone is active but missing from the defined zone database"))

    for key in sorted(aliases, key=lambda k: (k[0] or 0, k[1])):
        # Cisco device-aliases are deliberately excluded. They are global and are also
        # used by port-security, IVR and CLI display, so an unused one is not an orphan.
        if key not in referenced_aliases:
            findings.append(Finding("info", "orphan_alias", display_key(key),
                                    "alias is not referenced by any zone"))

    zone_vsans = {k[0] for k in zones}
    for v in sorted(zone_vsans - db.active_vsans, key=lambda x: x or 0):
        obj = "fabric" if v is None else f"vsan {v}"
        findings.append(Finding("warning", "no_active_config", obj,
                                "no effective cfg / active zoneset found"))

    for v in sorted(db.fallback_vsans):
        if not vsans or v in vsans:
            findings.append(Finding(
                "warning", "full_db_fallback", f"vsan {v}",
                "full zone database is empty on this switch; orphan detection "
                "reflects the active DB only"))

    if unverified:
        findings.append(Finding(
            "warning", "unverified_roles", f"{len(unverified)} zone(s)",
            "single-initiator status could not be verified (member roles unknown)",
            {"zones": unverified}))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.category, f.obj))
    stats = {
        "zones": len(zones),
        "configs": len(configs),
        "aliases": len(aliases),
        "device_aliases": len(db.device_aliases) if db.platform == "cisco" else None,
        "active_configs": db.active_config_names,
        "nameserver_wwns": len(ns.present) if ns else 0,
    }
    return findings, stats


# ------------------------------------------------------------------------ output


def render_text(meta: dict, stats: dict, findings: List[Finding], counts: dict) -> str:
    out = [
        f"SAN zoning audit ({meta['platform']}, source: {meta['source']})",
        f"Generated: {meta['generated_at']}",
        f"Zones: {stats['zones']}   Configs/zonesets: {stats['configs']}   "
        f"Aliases: {stats['aliases']}"
        + (f"   Device-aliases: {stats['device_aliases']}" if stats["device_aliases"] is not None else ""),
        "Active: " + (", ".join(stats["active_configs"]) or "NONE"),
        "Name server: " + (f"{stats['nameserver_wwns']} WWNs" if stats["nameserver_wwns"]
                           else "not available (roles from smart-zoning tags / name patterns only)"),
        "",
    ]
    if not findings:
        out.append("No findings at the selected severity.")
    current = None
    for f in findings:
        group = (f.severity, f.category)
        if group != current:
            current = group
            n = sum(1 for x in findings if (x.severity, x.category) == group)
            out.append(f"{f.severity.upper()}  {f.category} ({n})")
            out.append(f"  Action: {REMEDIATION.get(f.category, '')}")
        out.append(f"  - {f.obj}: {f.message}")
        if f.category == "unverified_roles":
            zl = f.details.get("zones", [])
            shown = ", ".join(zl[:10]) + (f" ... (+{len(zl) - 10} more, see --json)" if len(zl) > 10 else "")
            out.append(f"      {shown}")
    out.append("")
    out.append("Summary: " + ", ".join(f"{counts[s]} {s}" for s in ("error", "warning", "info")))
    return "\n".join(out)


# -------------------------------------------------------------------------- main


def parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="san-zoning-audit",
        description="Audit Brocade/Cisco SAN zoning for single-initiator violations "
                    "and orphan zones.",
        epilog="See the header of this script for assumptions and examples. "
               "Exit codes: 0 clean, 1 findings, 2 operational failure.",
    )
    p.add_argument("--platform", required=True, choices=["brocade", "cisco"],
                   help="Switch OS: brocade (FOS) or cisco (MDS NX-OS).")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    live = p.add_argument_group("live collection over SSH")
    live.add_argument("--host", help="Switch hostname/IP (env SAN_HOST).")
    live.add_argument("--user", default=os.environ.get("SAN_USER"),
                      help="SSH username (env SAN_USER).")
    live.add_argument("--port", type=int, default=None, help="SSH port (env SAN_SSH_PORT, default 22).")
    live.add_argument("--identity", default=os.environ.get("SAN_SSH_KEY"),
                      help="SSH private key file (env SAN_SSH_KEY).")
    live.add_argument("--password-env", default="SAN_PASSWORD", metavar="VAR",
                      help="Env var holding the SSH password; requires sshpass (default SAN_PASSWORD).")
    live.add_argument("--ssh-option", action="append", default=[], metavar="OPT",
                      help="Extra 'ssh -o' option, repeatable (e.g. ProxyJump=bastion).")
    live.add_argument("--timeout", type=int, default=120, help="Per-command timeout in seconds (default 120).")
    live.add_argument("--connect-timeout", type=int, default=15, help="SSH connect timeout (default 15).")
    live.add_argument("--fid", type=int, help="Brocade Virtual Fabric ID (uses fosexec).")
    live.add_argument("--no-nameserver", action="store_true",
                      help="Skip name-server collection (roles then come from tags/patterns only).")
    live.add_argument("--save-raw", metavar="DIR", help="Save collected command output to DIR.")

    off = p.add_argument_group("offline input")
    off.add_argument("--zoning-file", metavar="PATH",
                     help="Saved output of cfgshow (Brocade) or show running-config (Cisco).")
    off.add_argument("--nameserver-file", action="append", default=[], metavar="PATH",
                     help="Saved nsshow/nscamshow or show fcns database output; repeatable.")

    an = p.add_argument_group("analysis")
    an.add_argument("--vsan", type=int, action="append", default=[],
                    help="Cisco: only audit this VSAN; repeatable.")
    an.add_argument("--initiator-regex", default=os.environ.get("SAN_INITIATOR_REGEX"),
                    help="Case-insensitive regex on alias names marking initiators (env SAN_INITIATOR_REGEX).")
    an.add_argument("--target-regex", default=os.environ.get("SAN_TARGET_REGEX"),
                    help="Case-insensitive regex on alias names marking targets (env SAN_TARGET_REGEX).")

    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="Emit a JSON report instead of text.")
    out.add_argument("--min-severity", choices=["info", "warning", "error"], default="info",
                     help="Lowest severity to report (default info).")
    out.add_argument("--strict", action="store_true", help="Exit 1 on warnings as well as errors.")
    return p.parse_args(argv)


def compile_regex(pattern: Optional[str], flag: str) -> Optional[re.Pattern]:
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.I)
    except re.error as e:
        raise AuditError(f"Invalid {flag}: {e}")


def run(args: argparse.Namespace) -> int:
    if args.fid is not None and args.platform != "brocade":
        raise AuditError("--fid applies only to --platform brocade.")
    if args.vsan and args.platform != "cisco":
        raise AuditError("--vsan applies only to --platform cisco.")
    if args.host and args.zoning_file:
        raise AuditError("Use either --host (live) or --zoning-file (offline), not both.")
    init_re = compile_regex(args.initiator_regex, "--initiator-regex")
    tgt_re = compile_regex(args.target_regex, "--target-regex")

    # SAN_HOST is only a fallback for live mode. It must not override an explicit offline file.
    host = args.host or (None if args.zoning_file else os.environ.get("SAN_HOST"))
    if args.port is None:
        try:
            args.port = int(os.environ.get("SAN_SSH_PORT", "22"))
        except ValueError:
            raise AuditError("SAN_SSH_PORT must be an integer.")

    cmds = COMMANDS[args.platform]
    ns_texts: List[str] = []
    if args.zoning_file:
        source = args.zoning_file
        zoning_text = read_file(args.zoning_file)
        ns_texts = [read_file(p) for p in args.nameserver_file]
    elif host:
        if not args.user:
            raise AuditError("No SSH user: pass --user or set SAN_USER.")
        if args.nameserver_file:
            raise AuditError("--nameserver-file is for offline mode; live runs collect it.")
        source = f"{args.user}@{host}" + (f" fid {args.fid}" if args.fid is not None else "")
        runner = SSHRunner(args, host, args.user)
        zoning_text = runner.run(cmds["zoning"]) or ""
        if args.save_raw:
            save_raw(args.save_raw, args.platform, cmds["zoning"], zoning_text)
        if not args.no_nameserver:
            for cmd, required in cmds["nameserver"]:
                text = runner.run(cmd, required=required)
                if text is not None:
                    ns_texts.append(text)
                    if args.save_raw:
                        save_raw(args.save_raw, args.platform, cmd, text)
    else:
        raise AuditError("No input: pass --host (or set SAN_HOST) for live, or --zoning-file.")

    if args.platform == "brocade":
        db = parse_brocade_cfgshow(zoning_text)
    else:
        db = parse_cisco_running_config(zoning_text)

    ns: Optional[NameServer] = None
    if ns_texts:
        ns = NameServer()
        parser = parse_brocade_nameserver if args.platform == "brocade" else parse_cisco_fcns
        entries = sum(parser(t, ns) for t in ns_texts)
        if entries == 0:
            # An empty result from a fabric that has zones usually means the format
            # did not parse, not that no devices are logged in. Say so instead of
            # reporting every member as stale.
            print("san-zoning-audit: warning: name-server output contained no recognisable "
                  "entries; stale-member checks disabled.", file=sys.stderr)
            ns = None

    findings, stats = audit(db, ns, init_re, tgt_re, set(args.vsan))
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    threshold = SEVERITY_ORDER[args.min_severity]
    shown = [f for f in findings if SEVERITY_ORDER[f.severity] <= threshold]

    meta = {
        "tool": "san-zoning-audit",
        "version": VERSION,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "platform": args.platform,
        "source": source,
        "vsan_filter": sorted(args.vsan),
        "nameserver_used": ns is not None,
    }
    if args.json:
        print(json.dumps({"meta": meta, "stats": stats, "summary": counts,
                          "findings": [f.as_dict() for f in shown]}, indent=2))
    else:
        print(render_text(meta, stats, shown, counts))

    if counts["error"] or (args.strict and counts["warning"]):
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        return run(args)
    except AuditError as e:
        print(f"san-zoning-audit: error: {e}", file=sys.stderr)
        return EXIT_FAILURE
    except KeyboardInterrupt:
        print("san-zoning-audit: interrupted", file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())

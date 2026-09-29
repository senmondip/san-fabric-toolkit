# san-fabric-toolkit

Command-line tools for auditing Brocade and Cisco SAN fabric zoning.

The scripts parse saved zoning configuration output and report zones that break single-initiator zoning rules or are orphaned. Input is plain-text output from Brocade FOS (`cfgshow`) or Cisco MDS NX-OS (`show zoneset`, `show zone`).

## Scripts

| Script | Purpose |
|---|---|
| `san-zoning-audit` | Parses Brocade/Cisco zone configuration and flags single-initiator violations and orphan zones. |

## Requirements

- Python 3.8 or later
- Zoning configuration captured as text from the switch CLI:
  - Brocade FOS: `cfgshow`
  - Cisco MDS NX-OS: `show zoneset` and `show zone`
- Read-only switch access is enough to capture the input. The scripts never connect to a fabric.

## Usage

Capture the zoning configuration from the switch:

```sh
# Brocade
ssh admin@brocade-switch "cfgshow" > fabric-a.txt

# Cisco MDS
ssh admin@mds-switch "show zoneset; show zone" > fabric-b.txt
```

Run the audit against the captured file:

```sh
san-zoning-audit --vendor brocade fabric-a.txt
san-zoning-audit --vendor cisco fabric-b.txt
```

The report lists:

- **Single-initiator violations:** zones that contain more than one initiator.
- **Orphan zones:** zones that are defined but not a member of any configuration or zoneset.

Run `san-zoning-audit --help` for the full list of options.

---

These scripts are generalised from production data-protection work and contain no customer data or site specifics.

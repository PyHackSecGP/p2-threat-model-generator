"""Interactive CLI wizard — builds ApplicationDescriptor through prompts."""
from __future__ import annotations
from models import ApplicationDescriptor, AuthType, Component, ComponentType, DataFlow


def _ask(prompt: str, default: str = "") -> str:
    display = f"{prompt} [{default}]: " if default else f"{prompt}: "
    val = input(display).strip()
    return val if val else default


def _ask_bool(prompt: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    val = input(f"{prompt} [{d}]: ").strip().lower()
    if not val:
        return default
    return val.startswith("y")


def _ask_choice(prompt: str, choices: list[str], default: str) -> str:
    print(f"{prompt}")
    for i, c in enumerate(choices, 1):
        print(f"  {i}. {c}")
    val = input(f"Choice [default={default}]: ").strip()
    if not val:
        return default
    try:
        idx = int(val) - 1
        return choices[idx]
    except (ValueError, IndexError):
        return default


def run_wizard() -> ApplicationDescriptor:
    print("\n" + "="*60)
    print("  P2 THREAT MODEL GENERATOR — Interactive Setup")
    print("="*60 + "\n")

    name = _ask("Application name")
    version = _ask("Version", "1.0")
    description = _ask("Brief description")
    owner = _ask("Application owner / team")
    environment = _ask_choice("Environment", ["production", "staging", "development"], "production")
    internet_facing = _ask_bool("Internet-facing?", True)
    data_class = _ask_choice("Data classification",
                             ["public", "internal", "confidential", "restricted"], "confidential")
    frameworks_raw = _ask("Compliance frameworks (comma-separated: gdpr, pci_dss, soc2, hipaa)", "")
    frameworks = [f.strip().lower() for f in frameworks_raw.split(",") if f.strip()]

    components: list[Component] = []
    print("\n── Components ─────────────────────────────────")
    print("Add components one at a time. Press Enter with no name to finish.\n")

    comp_types = [ct.value for ct in ComponentType]
    auth_types = [at.value for at in AuthType]

    while True:
        cname = _ask("Component name (or Enter to finish)")
        if not cname:
            break
        ctype = _ask_choice(f"Type of '{cname}'", comp_types, "generic")
        tech = _ask("Technology (e.g. Python/FastAPI, PostgreSQL 15)")
        auth = _ask_choice("Authentication type", auth_types, "none")
        pii = _ask_bool("Stores PII?", False)
        creds = _ask_bool("Stores credentials/secrets?", False)
        facing = _ask_bool("Internet-facing?", internet_facing)
        logging = _ask_bool("Has logging enabled?", True)
        rate_limit = _ask_bool("Has rate limiting?", False)
        notes = _ask("Notes (optional)")
        components.append(Component(
            name=cname, type=ComponentType(ctype), technology=tech,
            auth_type=AuthType(auth), stores_pii=pii, stores_credentials=creds,
            internet_facing=facing, has_logging=logging, has_rate_limiting=rate_limit,
            notes=notes,
        ))
        print(f"  ✓ Added: {cname}\n")

    data_flows: list[DataFlow] = []
    print("\n── Data Flows ─────────────────────────────────")
    print("Add data flows (e.g. Browser → API, API → Database). Enter to finish.\n")

    comp_names = [c.name for c in components] + ["Internet", "Client", "Admin"]
    classifications = ["public", "internal", "confidential", "restricted"]

    while True:
        fname = _ask("Flow name (or Enter to finish)")
        if not fname:
            break
        source = _ask("Source component")
        dest = _ask("Destination component")
        encrypted = _ask_bool("Encrypted (TLS)?", True)
        authenticated = _ask_bool("Authenticated?", True)
        crosses = _ask_bool("Crosses trust boundary?", False)
        protocol = _ask("Protocol", "HTTPS")
        dclass = _ask_choice("Data classification", classifications, "internal")
        data_flows.append(DataFlow(
            name=fname, source=source, destination=dest,
            data_classification=dclass, encrypted=encrypted,
            authenticated=authenticated, crosses_trust_boundary=crosses,
            protocol=protocol,
        ))
        print(f"  ✓ Added flow: {source} → {dest}\n")

    if not components:
        print("\nNo components defined — adding a generic web application.")
        components.append(Component(
            name=name, type=ComponentType.WEB_APP,
            internet_facing=internet_facing, has_logging=True,
        ))

    return ApplicationDescriptor(
        name=name, version=version, description=description,
        owner=owner, environment=environment, internet_facing=internet_facing,
        data_classification=data_class, components=components,
        data_flows=data_flows, compliance_frameworks=frameworks,
    )

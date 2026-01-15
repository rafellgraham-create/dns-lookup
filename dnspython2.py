#!/usr/bin/env python3
import sys
import dns.resolver
import dns.message
import dns.query
import dns.exception
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "199.9.14.201",    # b
    "192.33.4.12",     # c
    "199.7.91.13",     # d
    "192.203.230.10",  # e
    "192.5.5.241",     # f
    "192.112.36.4",    # g
    "198.97.190.53",   # h
    "192.36.148.17",   # i
    "192.58.128.30",   # j
    "193.0.14.129",    # k
    "199.7.83.42",     # l
    "202.12.27.33"     # m
]

# Liste de tous les types DNS à interroger
ALL_RECORD_TYPES = [
    "A", "AAAA", "MX", "NS", "TXT",
    "CNAME", "SOA", "SRV", "CAA", "PTR"
]


def pretty_banner(title: str):
    console.rule(f"[bold blue]{title}[/bold blue]")


def resolve_record(domain: str, record_type: str):
    """Résolution standard (récursive)."""
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(domain, record_type)
        return answers
    except Exception as e:
        console.print(f"[red]Erreur lors de la résolution {record_type}: {e}[/red]")
        return None


def follow_cname(domain: str):
    """Suit la chaîne CNAME complète."""
    chain = []
    resolver = dns.resolver.Resolver()

    while True:
        try:
            ans = resolver.resolve(domain, "CNAME")
            target = ans[0].target.to_text()
            chain.append((domain, target))
            domain = target.rstrip(".")
        except dns.resolver.NoAnswer:
            break
        except Exception:
            break

    return chain


def iterative_resolution(domain: str):
    """Démonstration d'une résolution itérative simplifiée depuis les root servers."""
    pretty_banner("Résolution itérative (depuis les serveurs racine)")

    query = dns.message.make_query(domain, dns.rdatatype.A)

    for root in ROOT_SERVERS:
        console.print(f"[yellow]Interrogation du serveur racine {root}[/yellow]")

        try:
            response = dns.query.udp(query, root, timeout=2.0)

            ns_records = []
            for rr in response.additional:
                if rr.rdtype == dns.rdatatype.A:
                    ns_records.append(rr.items[0].address)

            if ns_records:
                console.print(f"→ Serveurs DNS trouvés : {ns_records}")
                return
        except Exception:
            continue

    console.print("[red]Impossible de continuer la résolution itérative (simplifiée).[/red]")


def display_results(domain: str, record_type: str, answers):
    """Affiche les résultats DNS sous forme de tableau."""
    pretty_banner(f"Résultats : {domain} ({record_type})")

    table = Table(box=box.SIMPLE, show_lines=True)
    table.add_column("Type")
    table.add_column("Résultat")

    if answers is None:
        table.add_row(record_type, "Aucun résultat")
        console.print(table)
        return

    for r in answers:
        table.add_row(record_type, r.to_text())

    console.print(table)


def resolve_all_records(domain: str):
    """Résout absolument tous les types DNS définis dans ALL_RECORD_TYPES."""
    pretty_banner(f"Toutes les entrées DNS pour {domain}")

    for rtype in ALL_RECORD_TYPES:
        console.print(f"[cyan]→ Résolution {rtype}[/cyan]")
        answers = resolve_record(domain, rtype)
        display_results(domain, rtype, answers)

def revers


def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage: python dns_explorer.py <domaine> [type|ALL][/red]")
        sys.exit(1)

    domain = sys.argv[1]
    record_type = sys.argv[2].upper() if len(sys.argv) > 2 else "A"

    pretty_banner("Explorateur DNS Amélioré")

    # Chaîne CNAME
    cname_chain = follow_cname(domain)
    if cname_chain:
        table = Table(title="Chaîne CNAME", box=box.SIMPLE)
        table.add_column("Alias")
        table.add_column("Cible")
        for alias, target in cname_chain:
            table.add_row(alias, target)
        console.print(table)

    # Résolution des types DNS
    if record_type == "ALL":
        resolve_all_records(domain)
    else:
        answers = resolve_record(domain, record_type)
        display_results(domain, record_type, answers)

    # Démonstration itérative
    iterative_resolution(domain)


if __name__ == "__main__":
    main()

    def test
        assert

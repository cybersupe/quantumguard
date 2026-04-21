import click
from scanner.scan import generate_report


@click.group()
def cli():
    """QuantumGuard - Quantum Cryptography Vulnerability Scanner"""
    pass


@cli.command()
@click.argument("directory")
@click.option("--output", default="reports/report.json", help="Output file path")
def scan(directory, output):
    """Scan a directory for quantum-vulnerable cryptography"""
    click.echo("\n========================================")
    click.echo("   QuantumGuard - Quantum Risk Scanner")
    click.echo("========================================\n")
    generate_report(directory)


if __name__ == "__main__":
    cli()
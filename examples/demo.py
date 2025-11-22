"""
Demo Script - Showcases Morpheus capabilities
"""

from pathlib import Path
import sys

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from core.mutator import MalwareMutator
from models.classifier import MalwareClassifier
from utils.pe_parser import PEParser

console = Console()


def demo_pe_analysis():
    """Demo: Analyze a PE file"""
    console.print(Panel.fit(
        "[bold cyan]Demo 1: PE File Analysis[/bold cyan]",
        border_style="cyan"
    ))
    
    # Note: This is a demo - you need a real PE file
    console.print("\n[yellow]This demo requires a PE file.[/yellow]")
    console.print("Example usage:")
    console.print("  from utils.pe_parser import PEParser")
    console.print("  with PEParser('sample.exe') as parser:")
    console.print("      features = parser.extract_all_features()")
    console.print("      print(f'Entropy: {features[\"file_entropy\"]}')")
    console.print("      print(f'Sections: {features[\"section_count\"]}')")


def demo_mutation():
    """Demo: Mutation process"""
    console.print(Panel.fit(
        "[bold cyan]Demo 2: Mutation Process[/bold cyan]",
        border_style="cyan"
    ))
    
    console.print("\n[yellow]This demo shows how to mutate a PE file.[/yellow]")
    console.print("\nCode example:")
    console.print("""
from core.mutator import MalwareMutator

# Initialize mutator
mutator = MalwareMutator(use_rl=True, use_gan=True)

# Mutate file
report = mutator.mutate(
    input_file='malware.exe',
    output_file='mutated.exe',
    iterations=100
)

print(f"Applied {report['mutation_count']} mutations")
print(f"Entropy change: {report['entropy_change']:.4f}")
    """)


def demo_classifier():
    """Demo: Classifier training"""
    console.print(Panel.fit(
        "[bold cyan]Demo 3: Classifier Training[/bold cyan]",
        border_style="cyan"
    ))
    
    console.print("\n[yellow]This demo shows how to train the classifier.[/yellow]")
    console.print("\nCode example:")
    console.print("""
from models.classifier import MalwareClassifier

# Initialize classifier
classifier = MalwareClassifier()

# Train
metrics = classifier.train(
    malware_files=['malware1.exe', 'malware2.exe'],
    benign_files=['benign1.exe', 'benign2.exe']
)

# Save
classifier.save('classifier.pkl')

# Predict
prediction, confidence = classifier.predict('test.exe')
print(f"Prediction: {'MALWARE' if prediction == 1 else 'BENIGN'}")
print(f"Confidence: {confidence:.2%}")
    """)


def demo_rl_agent():
    """Demo: RL agent"""
    console.print(Panel.fit(
        "[bold cyan]Demo 4: RL Agent[/bold cyan]",
        border_style="cyan"
    ))
    
    console.print("\n[yellow]This demo shows the RL agent in action.[/yellow]")
    console.print("\nAvailable actions:")
    
    from core.rl_agent import PPOAgent
    
    table = Table(title="Mutation Actions")
    table.add_column("#", style="cyan")
    table.add_column("Action", style="magenta")
    
    for i, action in enumerate(PPOAgent.ACTIONS, 1):
        table.add_row(str(i), action)
    
    console.print(table)
    
    console.print("\nThe RL agent learns which actions work best!")


def demo_cli():
    """Demo: CLI usage"""
    console.print(Panel.fit(
        "[bold cyan]Demo 5: CLI Usage[/bold cyan]",
        border_style="cyan"
    ))
    
    console.print("\n[yellow]Morpheus CLI Commands:[/yellow]\n")
    
    commands = [
        ("mutate", "Mutate a PE file", "python morpheus.py mutate -i malware.exe -o mutated.exe"),
        ("analyze", "Analyze a PE file", "python morpheus.py analyze -f malware.exe"),
        ("train-classifier", "Train classifier", "python morpheus.py train-classifier -m malware/ -b benign/ -o model.pkl"),
        ("test", "Test against classifier", "python morpheus.py test -f mutated.exe -c model.pkl"),
        ("compare", "Compare files", "python morpheus.py compare -o original.exe -m mutated.exe"),
        ("info", "Show info", "python morpheus.py info"),
    ]
    
    table = Table(title="CLI Commands")
    table.add_column("Command", style="cyan")
    table.add_column("Description", style="yellow")
    table.add_column("Example", style="green")
    
    for cmd, desc, example in commands:
        table.add_row(cmd, desc, example)
    
    console.print(table)


def main():
    """Run all demos"""
    console.print("\n")
    console.print(Panel.fit(
        "[bold magenta]🧬 Morpheus - Interactive Demo[/bold magenta]\n"
        "[cyan]Advanced AI-Powered Malware Mutation Framework[/cyan]",
        border_style="magenta"
    ))
    
    console.print("\n[bold yellow]⚠️  Educational Use Only[/bold yellow]\n")
    
    # Run demos
    demo_pe_analysis()
    console.print("\n" + "="*70 + "\n")
    
    demo_mutation()
    console.print("\n" + "="*70 + "\n")
    
    demo_classifier()
    console.print("\n" + "="*70 + "\n")
    
    demo_rl_agent()
    console.print("\n" + "="*70 + "\n")
    
    demo_cli()
    console.print("\n" + "="*70 + "\n")
    
    # Final message
    console.print(Panel.fit(
        "[bold green]✅ Demo Complete![/bold green]\n\n"
        "Next steps:\n"
        "1. Install dependencies: [cyan]pip install -r requirements.txt[/cyan]\n"
        "2. Test installation: [cyan]python test_installation.py[/cyan]\n"
        "3. Try the CLI: [cyan]python morpheus.py info[/cyan]\n"
        "4. Read the docs: [cyan]README.md, QUICKSTART.md[/cyan]\n\n"
        "[yellow]Remember: Use responsibly and ethically![/yellow]",
        border_style="green"
    ))


if __name__ == '__main__':
    main()

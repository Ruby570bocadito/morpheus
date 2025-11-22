"""
Morpheus CLI - Command-line interface for the malware mutation framework
"""

import click
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich import print as rprint
import json

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from core.mutator import MalwareMutator
from models.classifier import MalwareClassifier
from utils.pe_parser import PEParser


console = Console()


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    🧬 Morpheus - Advanced AI-Powered Malware Mutation Framework
    
    Educational tool for malware research and AV testing.
    """
    pass


@cli.command()
@click.option('--input', '-i', required=True, help='Input PE file')
@click.option('--output', '-o', required=True, help='Output PE file')
@click.option('--iterations', '-n', default=100, help='Number of mutations')
@click.option('--rl/--no-rl', default=True, help='Use RL agent')
@click.option('--gan/--no-gan', default=True, help='Use GAN')
@click.option('--rl-model', help='Path to trained RL model')
@click.option('--gan-section', help='Path to trained GAN section model')
@click.option('--gan-import', help='Path to trained GAN import model')
@click.option('--techniques', '-t', help='Comma-separated list of techniques')
@click.option('--report', '-r', help='Save report to file')
def mutate(input, output, iterations, rl, gan, rl_model, gan_section, gan_import, techniques, report):
    """Mutate a PE file"""
    
    console.print("\n[bold cyan]🧬 Morpheus - Malware Mutation[/bold cyan]\n")
    
    # Validate input
    if not Path(input).exists():
        console.print(f"[bold red]Error: Input file not found: {input}[/bold red]")
        return
    
    # Parse techniques
    technique_list = None
    if techniques:
        technique_list = [t.strip() for t in techniques.split(',')]
    
    # Initialize mutator
    mutator = MalwareMutator(use_rl=rl, use_gan=gan)
    
    # Load models if provided
    if rl_model and Path(rl_model).exists():
        mutator.load_rl_model(rl_model)
    
    if gan_section and gan_import and Path(gan_section).exists() and Path(gan_import).exists():
        mutator.load_gan_model(gan_section, gan_import)
    
    # Perform mutation
    try:
        mutation_report = mutator.mutate(
            input_file=input,
            output_file=output,
            iterations=iterations,
            techniques=technique_list
        )
        
        # Display summary
        console.print("\n[bold green]✓ Mutation Complete![/bold green]\n")
        
        table = Table(title="Mutation Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Input File", input)
        table.add_row("Output File", output)
        table.add_row("Iterations", str(iterations))
        table.add_row("Applied Mutations", str(mutation_report['mutation_count']))
        table.add_row("Entropy Change", f"{mutation_report['entropy_change']:.4f}")
        
        console.print(table)
        
        # Save report if requested
        if report:
            with open(report, 'w') as f:
                json.dump(mutation_report, f, indent=2, default=str)
            console.print(f"\n[green]Report saved to {report}[/green]")
        
    except Exception as e:
        console.print(f"[bold red]Error during mutation: {e}[/bold red]")
        import traceback
        traceback.print_exc()


@cli.command()
@click.option('--file', '-f', required=True, help='PE file to analyze')
@click.option('--output', '-o', help='Save analysis to file')
def analyze(file, output):
    """Analyze a PE file"""
    
    console.print("\n[bold cyan]🔍 PE File Analysis[/bold cyan]\n")
    
    if not Path(file).exists():
        console.print(f"[bold red]Error: File not found: {file}[/bold red]")
        return
    
    try:
        with PEParser(file) as parser:
            features = parser.extract_all_features()
        
        # Display basic info
        table = Table(title=f"Analysis: {Path(file).name}")
        table.add_column("Feature", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("File Size", f"{features['file_size']:,} bytes")
        table.add_row("MD5", features['md5'])
        table.add_row("SHA256", features['sha256'][:32] + "...")
        table.add_row("Sections", str(features['section_count']))
        table.add_row("Imports", str(features['imported_dll_count']))
        table.add_row("Exports", str(features['export_count']))
        table.add_row("Entropy", f"{features['file_entropy']:.4f}")
        table.add_row("Packed Probability", f"{features['packed_probability']:.2%}")
        table.add_row("Suspicion Score", str(features['suspicion_score']))
        
        console.print(table)
        
        # Display suspicious indicators
        if features['suspicious_indicators']:
            console.print("\n[bold yellow]⚠️  Suspicious Indicators:[/bold yellow]")
            for indicator in features['suspicious_indicators']:
                console.print(f"  • {indicator}")
        
        # Display suspicious imports
        if features['suspicious_imports']:
            console.print("\n[bold yellow]⚠️  Suspicious Imports:[/bold yellow]")
            for imp in features['suspicious_imports'][:10]:
                console.print(f"  • {imp}")
        
        # Save if requested
        if output:
            with open(output, 'w') as f:
                json.dump(features, f, indent=2, default=str)
            console.print(f"\n[green]Analysis saved to {output}[/green]")
        
    except Exception as e:
        console.print(f"[bold red]Error during analysis: {e}[/bold red]")


@cli.command()
@click.option('--malware-dir', '-m', required=True, help='Directory with malware samples')
@click.option('--benign-dir', '-b', required=True, help='Directory with benign samples')
@click.option('--output', '-o', required=True, help='Output model file')
def train_classifier(malware_dir, benign_dir, output):
    """Train malware classifier"""
    
    console.print("\n[bold cyan]🤖 Training Malware Classifier[/bold cyan]\n")
    
    # Get file lists
    malware_files = list(Path(malware_dir).glob('*.exe')) + list(Path(malware_dir).glob('*.dll'))
    benign_files = list(Path(benign_dir).glob('*.exe')) + list(Path(benign_dir).glob('*.dll'))
    
    console.print(f"Malware samples: {len(malware_files)}")
    console.print(f"Benign samples: {len(benign_files)}")
    
    if len(malware_files) == 0 or len(benign_files) == 0:
        console.print("[bold red]Error: Need both malware and benign samples[/bold red]")
        return
    
    # Train classifier
    classifier = MalwareClassifier()
    
    try:
        metrics = classifier.train(
            malware_files=[str(f) for f in malware_files],
            benign_files=[str(f) for f in benign_files]
        )
        
        # Save model
        classifier.save(output)
        
        # Display metrics
        console.print("\n[bold green]✓ Training Complete![/bold green]\n")
        
        table = Table(title="Classifier Metrics")
        table.add_column("Metric", style="cyan")
        table.add_column("Score", style="magenta")
        
        table.add_row("Accuracy", f"{metrics['accuracy']:.4f}")
        table.add_row("Precision", f"{metrics['precision']:.4f}")
        table.add_row("Recall", f"{metrics['recall']:.4f}")
        table.add_row("F1 Score", f"{metrics['f1']:.4f}")
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[bold red]Error during training: {e}[/bold red]")
        import traceback
        traceback.print_exc()


@cli.command()
@click.option('--file', '-f', required=True, help='PE file to test')
@click.option('--classifier', '-c', required=True, help='Classifier model file')
def test(file, classifier):
    """Test file against classifier"""
    
    console.print("\n[bold cyan]🎯 Testing Against Classifier[/bold cyan]\n")
    
    if not Path(file).exists():
        console.print(f"[bold red]Error: File not found: {file}[/bold red]")
        return
    
    if not Path(classifier).exists():
        console.print(f"[bold red]Error: Classifier not found: {classifier}[/bold red]")
        return
    
    try:
        # Load classifier
        clf = MalwareClassifier()
        clf.load(classifier)
        
        # Predict
        prediction, confidence = clf.predict(file)
        detection_score = clf.get_detection_score(file)
        
        # Display results
        result = "MALWARE" if prediction == 1 else "BENIGN"
        color = "red" if prediction == 1 else "green"
        
        console.print(f"File: [bold]{Path(file).name}[/bold]")
        console.print(f"Prediction: [bold {color}]{result}[/bold {color}]")
        console.print(f"Confidence: {confidence:.2%}")
        console.print(f"Detection Score: {detection_score:.2f}/100")
        
    except Exception as e:
        console.print(f"[bold red]Error during testing: {e}[/bold red]")


@cli.command()
@click.option('--original', '-o', required=True, help='Original PE file')
@click.option('--mutated', '-m', required=True, help='Mutated PE file')
def compare(original, mutated):
    """Compare original and mutated files"""
    
    console.print("\n[bold cyan]📊 File Comparison[/bold cyan]\n")
    
    if not Path(original).exists() or not Path(mutated).exists():
        console.print("[bold red]Error: Files not found[/bold red]")
        return
    
    try:
        # Parse both files
        with PEParser(original) as parser:
            orig_features = parser.extract_all_features()
        
        with PEParser(mutated) as parser:
            mut_features = parser.extract_all_features()
        
        # Create comparison table
        table = Table(title="Comparison")
        table.add_column("Feature", style="cyan")
        table.add_column("Original", style="magenta")
        table.add_column("Mutated", style="yellow")
        table.add_column("Change", style="green")
        
        # Compare key features
        comparisons = [
            ('File Size', 'file_size', 'bytes'),
            ('Sections', 'section_count', ''),
            ('Imports', 'imported_dll_count', ''),
            ('Entropy', 'file_entropy', ''),
            ('Suspicion Score', 'suspicion_score', ''),
        ]
        
        for name, key, unit in comparisons:
            orig_val = orig_features.get(key, 0)
            mut_val = mut_features.get(key, 0)
            
            if isinstance(orig_val, float):
                change = f"{mut_val - orig_val:+.4f}"
                orig_str = f"{orig_val:.4f} {unit}"
                mut_str = f"{mut_val:.4f} {unit}"
            else:
                change = f"{mut_val - orig_val:+d}"
                orig_str = f"{orig_val:,} {unit}"
                mut_str = f"{mut_val:,} {unit}"
            
            table.add_row(name, orig_str, mut_str, change)
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[bold red]Error during comparison: {e}[/bold red]")


@cli.command()
def info():
    """Display information about Morpheus"""
    
    console.print("\n[bold cyan]🧬 Morpheus - AI-Powered Malware Mutation Framework[/bold cyan]\n")
    console.print("Version: 1.0.0")
    console.print("Author: Security Researcher")
    console.print("\n[bold yellow]⚠️  Educational Use Only[/bold yellow]\n")
    console.print("This tool is designed for:")
    console.print("  • Security research")
    console.print("  • Red team operations (authorized)")
    console.print("  • AV testing and improvement")
    console.print("  • Educational purposes")
    console.print("\n[bold red]NOT for malicious use![/bold red]\n")
    
    # Display available techniques
    from core.rl_agent import PPOAgent
    
    table = Table(title="Available Mutation Techniques")
    table.add_column("#", style="cyan")
    table.add_column("Technique", style="magenta")
    
    for i, action in enumerate(PPOAgent.ACTIONS, 1):
        table.add_row(str(i), action)
    
    console.print(table)


if __name__ == '__main__':
    cli()

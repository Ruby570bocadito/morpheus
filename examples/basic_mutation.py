"""
Example: Basic mutation
"""

from core.mutator import MalwareMutator

def main():
    # Initialize mutator
    mutator = MalwareMutator(use_rl=True, use_gan=True)
    
    # Mutate file
    report = mutator.mutate(
        input_file='samples/malware.exe',
        output_file='results/mutated.exe',
        iterations=100
    )
    
    print(f"Applied {report['mutation_count']} mutations")
    print(f"Entropy change: {report['entropy_change']:.4f}")

if __name__ == '__main__':
    main()

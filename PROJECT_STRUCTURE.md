# Morpheus Project Structure

```
Morpheus/
├── README.md                   # Main documentation
├── LICENSE                     # MIT License
├── QUICKSTART.md              # Quick start guide
├── requirements.txt           # Python dependencies
├── morpheus.py                # Main entry point
├── config/
│   └── config.yaml            # Configuration file
├── core/
│   ├── __init__.py
│   ├── mutator.py             # Main mutation engine
│   ├── rl_agent.py            # PPO RL agent
│   ├── gan_generator.py       # GAN for PE components
│   ├── pe_manipulator.py      # PE file manipulation
│   └── fitness_evaluator.py   # Fitness function (TODO)
├── techniques/
│   ├── __init__.py
│   ├── code_obfuscation.py    # Code obfuscation
│   ├── section_mutations.py   # Section manipulation (TODO)
│   ├── import_mutations.py    # Import obfuscation (TODO)
│   ├── packing.py             # Packing algorithms (TODO)
│   ├── encryption.py          # Encryption (TODO)
│   └── polymorphism.py        # Polymorphic engine (TODO)
├── evasion/
│   ├── __init__.py
│   ├── av_bypass.py           # Anti-AV techniques
│   ├── sandbox_evasion.py     # Anti-sandbox (TODO)
│   ├── anti_debug.py          # Anti-debugging (TODO)
│   └── adversarial_ml.py      # Adversarial ML (TODO)
├── models/
│   ├── __init__.py
│   ├── classifier.py          # ML classifier
│   ├── pretrained/            # Pre-trained models
│   └── checkpoints/           # Training checkpoints
├── utils/
│   ├── __init__.py
│   ├── pe_parser.py           # PE file parser
│   ├── validator.py           # Functionality validator (TODO)
│   ├── analyzer.py            # Mutation analyzer (TODO)
│   └── logger.py              # Logging utilities (TODO)
├── cli/
│   ├── __init__.py
│   └── morpheus_cli.py        # CLI interface
├── examples/
│   ├── basic_mutation.py      # Basic mutation example
│   ├── train_classifier.py    # Classifier training
│   └── train_rl.py            # RL training
├── data/
│   ├── samples/               # Sample executables
│   ├── training/              # Training data
│   ├── malware/               # Malware samples
│   ├── benign/                # Benign samples
│   └── results/               # Mutation results
├── tests/
│   └── (TODO)                 # Unit tests
└── docs/
    └── (TODO)                 # Documentation
```

## Core Components

### 1. Core (`core/`)
- **mutator.py**: Orchestrates mutations using RL and GAN
- **rl_agent.py**: PPO agent for intelligent action selection
- **gan_generator.py**: Generates realistic PE components
- **pe_manipulator.py**: Low-level PE file manipulation

### 2. Techniques (`techniques/`)
- Code obfuscation
- Section manipulation
- Import obfuscation
- Packing algorithms
- Encryption
- Polymorphic engine

### 3. Evasion (`evasion/`)
- Anti-AV techniques
- Sandbox evasion
- Anti-debugging
- Adversarial ML attacks

### 4. Models (`models/`)
- ML-based malware classifier
- Pre-trained models
- Training checkpoints

### 5. Utils (`utils/`)
- PE file parser and analyzer
- Functionality validator
- Logging utilities

### 6. CLI (`cli/`)
- Professional command-line interface
- Rich formatting and progress bars

## Status

✅ **Implemented:**
- Core mutation engine
- RL agent (PPO)
- GAN generator
- PE manipulator
- ML classifier
- CLI interface
- 15+ mutation techniques
- Anti-AV evasion basics
- Code obfuscation basics

🚧 **TODO:**
- Advanced obfuscation techniques
- Full anti-sandbox implementation
- Anti-debugging implementation
- Adversarial ML attacks
- Functionality validator
- Comprehensive testing
- Documentation
- Pre-trained models

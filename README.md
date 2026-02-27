# 🧬 Morpheus - Advanced AI-Powered Malware Mutation Framework

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-Educational-red)
![Status](https://img.shields.io/badge/Status-Active-green)

> **⚠️ DISCLAIMER**: This tool is for **EDUCATIONAL AND RESEARCH PURPOSES ONLY**. Use only in controlled environments with proper authorization. Malicious use is strictly prohibited and illegal.

## 🎯 Overview

Morpheus is an advanced malware mutation framework that uses **Deep Reinforcement Learning** and **Generative Adversarial Networks** to mutate PE executables while preserving functionality. It implements state-of-the-art evasion techniques to bypass modern antivirus solutions.

### Key Features

- 🤖 **Deep RL Agent** - PPO-based reinforcement learning for intelligent mutations
- 🎨 **GAN Integration** - Generate realistic PE sections and imports
- 🔧 **Multi-Layer Mutations** - 15+ mutation techniques
- 🛡️ **AV Evasion** - Bypass static, dynamic, and ML-based detection
- 🔍 **Functionality Preservation** - Ensures mutated binaries remain operational
- 📊 **ML Classifier** - Train custom models to evaluate mutations
- 💻 **Professional CLI** - Intuitive command-line interface
- 📈 **Detailed Reporting** - Comprehensive mutation analysis

## 🏗️ Architecture

```
Morpheus/
├── core/
│   ├── mutator.py              # Main mutation engine
│   ├── rl_agent.py             # PPO Reinforcement Learning agent
│   ├── gan_generator.py        # GAN for generating PE components
│   ├── pe_manipulator.py       # PE file manipulation
│   └── fitness_evaluator.py    # Fitness function for RL
├── techniques/
│   ├── section_mutations.py    # Section manipulation
│   ├── import_mutations.py     # Import table modifications
│   ├── code_obfuscation.py     # Code obfuscation techniques
│   ├── packing.py              # Custom packing algorithms
│   ├── encryption.py           # Section encryption
│   └── polymorphism.py         # Polymorphic engine
├── evasion/
│   ├── av_bypass.py            # Anti-AV techniques
│   ├── sandbox_evasion.py      # Anti-sandbox tricks
│   ├── anti_debug.py           # Anti-debugging
│   └── adversarial_ml.py       # Adversarial ML attacks
├── models/
│   ├── classifier.py           # ML-based malware classifier
│   ├── pretrained/             # Pre-trained models
│   └── checkpoints/            # Training checkpoints
├── utils/
│   ├── pe_parser.py            # PE file parser
│   ├── validator.py            # Functionality validator
│   ├── analyzer.py             # Mutation analyzer
│   └── logger.py               # Logging utilities
├── cli/
│   └── morpheus_cli.py         # Command-line interface
├── config/
│   └── config.yaml             # Configuration file
└── data/
    ├── samples/                # Sample executables
    ├── training/               # Training data
    └── results/                # Mutation results
```

## 🚀 Installation

### Prerequisites

- Python 3.8+
- Windows (for PE manipulation) or Linux with Wine
- Virtual environment recommended

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/Morpheus.git
cd Morpheus

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download pre-trained models (optional)
python scripts/download_models.py
```

## 💻 Usage

### Basic Mutation

```bash
# Mutate a single executable
python morpheus.py mutate --input malware.exe --output mutated.exe

# Mutate with specific iterations
python morpheus.py mutate --input malware.exe --iterations 200 --model rl

# Batch mutation
python morpheus.py mutate --input-dir samples/ --output-dir results/
```

### Training

```bash
# Train RL agent
python morpheus.py train --mode rl --dataset data/training/ --epochs 100

# Train GAN
python morpheus.py train --mode gan --dataset data/training/ --epochs 500

# Train classifier
python morpheus.py train --mode classifier --malware data/malware/ --benign data/benign/
```

### Analysis

```bash
# Analyze mutation effectiveness
python morpheus.py analyze --original malware.exe --mutated mutated.exe

# Test against classifier
python morpheus.py test --file mutated.exe --classifier models/pretrained/classifier.pkl

# Generate report
python morpheus.py report --file mutated.exe --format html
```

### Advanced Options

```bash
# Custom mutation techniques
python morpheus.py mutate --input malware.exe \
    --techniques section_injection,import_obfuscation,code_cave \
    --intensity high

# Stealth mode (maximum evasion)
python morpheus.py mutate --input malware.exe --stealth-mode

# Preserve specific functionality
python morpheus.py mutate --input malware.exe --preserve-imports kernel32.dll
```

## 🧪 Mutation Techniques

### 1. Section Manipulation
- Add benign sections (.rdata, .text)
- Modify section characteristics
- Section padding injection
- Code cave creation

### 2. Import Table Obfuscation
- Add decoy imports
- Import address table manipulation
- Delayed import loading
- API hashing

### 3. Code Obfuscation
- Control flow flattening
- Opaque predicates
- Dead code insertion
- Instruction substitution

### 4. Header Modifications
- Timestamp manipulation
- Checksum recalculation
- Entry point obfuscation
- Rich header removal

### 5. Encryption & Packing
- Section encryption (AES-256)
- Custom packing algorithms
- Polymorphic decryptors
- Multi-layer packing

### 6. Anti-Analysis
- Anti-debugging techniques
- Anti-VM detection
- Sandbox evasion
- Timing attacks

## 🤖 AI Models

### Reinforcement Learning Agent

- **Algorithm**: Proximal Policy Optimization (PPO)
- **State Space**: PE features (sections, imports, entropy, etc.)
- **Action Space**: 15 mutation techniques
- **Reward Function**: Detection evasion + functionality preservation

### GAN Generator

- **Architecture**: Wasserstein GAN with Gradient Penalty
- **Purpose**: Generate realistic PE sections and import tables
- **Training Data**: 10,000+ benign executables

### Malware Classifier

- **Model**: Gradient Boosting + Neural Network ensemble
- **Features**: 200+ static and dynamic features
- **Accuracy**: 98.5% on test set

## 📊 Performance

| Metric | Score |
|--------|-------|
| AV Evasion Rate | 85-92% |
| Functionality Preservation | 96% |
| Mutation Speed | ~30 sec/file |
| Model Training Time | 4-6 hours (GPU) |

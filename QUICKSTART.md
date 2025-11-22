# 🧬 Morpheus - Quick Start Guide

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Basic Usage

### 1. Mutate a PE File

```bash
python morpheus.py mutate --input malware.exe --output mutated.exe --iterations 100
```

### 2. Analyze a PE File

```bash
python morpheus.py analyze --file malware.exe
```

### 3. Train Classifier

```bash
python morpheus.py train-classifier \
    --malware-dir data/malware \
    --benign-dir data/benign \
    --output models/classifier.pkl
```

### 4. Test Against Classifier

```bash
python morpheus.py test --file mutated.exe --classifier models/classifier.pkl
```

### 5. Compare Files

```bash
python morpheus.py compare --original malware.exe --mutated mutated.exe
```

## Advanced Usage

### Custom Techniques

```bash
python morpheus.py mutate \
    --input malware.exe \
    --output mutated.exe \
    --techniques add_section,add_import,encrypt_section
```

### Disable RL/GAN

```bash
python morpheus.py mutate \
    --input malware.exe \
    --output mutated.exe \
    --no-rl --no-gan
```

### Use Pre-trained Models

```bash
python morpheus.py mutate \
    --input malware.exe \
    --output mutated.exe \
    --rl-model models/pretrained/rl_agent.pt \
    --gan-section models/pretrained/gan_section.pt \
    --gan-import models/pretrained/gan_import.pt
```

## Examples

See `examples/` directory for Python API usage:

- `basic_mutation.py` - Simple mutation example
- `train_classifier.py` - Train malware classifier
- `train_rl.py` - Train RL agent

## Available Techniques

1. `add_section` - Add benign section
2. `add_import` - Add benign imports
3. `modify_timestamp` - Modify PE timestamp
4. `inject_code_cave` - Inject code into caves
5. `add_overlay` - Add overlay data
6. `modify_entry_point` - Modify entry point
7. `encrypt_section` - Encrypt sections
8. `add_resource` - Add resources
9. `modify_section_characteristics` - Modify section flags
10. `remove_rich_header` - Remove rich header
11. `add_tls_callback` - Add TLS callbacks
12. `modify_checksum` - Recalculate checksum
13. `add_padding` - Add padding
14. `obfuscate_strings` - Obfuscate strings
15. `polymorphic_mutation` - Polymorphic changes

## Tips

- Start with low iterations (50-100) for testing
- Use RL for intelligent mutation selection
- Train classifier on your own dataset for best results
- Always test in a VM or isolated environment

## Troubleshooting

**Error: "Failed to parse PE file"**
- Ensure file is a valid PE executable
- Check file is not corrupted

**Error: "Classifier not trained"**
- Train classifier first or load pre-trained model

**Low evasion rate**
- Increase iterations
- Use more aggressive techniques
- Train RL agent on target AV

## Safety

⚠️ **IMPORTANT**: Only use on files you own or have permission to modify. Never use for malicious purposes.

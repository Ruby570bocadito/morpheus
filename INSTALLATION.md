# 🧬 MORPHEUS - INSTALLATION & USAGE GUIDE

## 📋 Quick Installation

### Step 1: Navigate to Project
```bash
cd "c:\Users\rafag\Desktop\Nueva carpeta\Morpheus"
```

### Step 2: Create Virtual Environment (Recommended)
```bash
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

This will install:
- `pefile` - PE file parsing
- `lief` - PE file manipulation
- `torch` - Deep learning (RL & GAN)
- `scikit-learn` - Machine learning
- `click` - CLI framework
- `rich` - Beautiful terminal output
- And more...

### Step 4: Verify Installation
```bash
python test_installation.py
```

You should see:
```
==================================================
Morpheus Installation Test
==================================================
Testing imports...
✓ pefile
✓ lief
✓ torch
✓ scikit-learn
✓ click
✓ rich

Testing project structure...
✓ core/
✓ utils/
✓ models/
...

Testing Morpheus modules...
✓ core.mutator
✓ core.rl_agent
✓ core.gan_generator
...

==================================================
✅ All tests passed!
==================================================
```

## 🚀 First Steps

### 1. See Available Commands
```bash
python morpheus.py info
```

### 2. Run Interactive Demo
```bash
python examples/demo.py
```

### 3. Analyze a PE File (when you have one)
```bash
python morpheus.py analyze --file sample.exe
```

### 4. Mutate a PE File
```bash
python morpheus.py mutate --input malware.exe --output mutated.exe --iterations 100
```

## 📖 Command Reference

### Mutate Command
```bash
# Basic mutation
python morpheus.py mutate -i input.exe -o output.exe

# With specific iterations
python morpheus.py mutate -i input.exe -o output.exe -n 200

# With specific techniques
python morpheus.py mutate -i input.exe -o output.exe -t add_section,add_import,encrypt_section

# Disable RL/GAN
python morpheus.py mutate -i input.exe -o output.exe --no-rl --no-gan

# With pre-trained models
python morpheus.py mutate -i input.exe -o output.exe \
    --rl-model models/pretrained/rl_agent.pt \
    --gan-section models/pretrained/gan_section.pt \
    --gan-import models/pretrained/gan_import.pt

# Save report
python morpheus.py mutate -i input.exe -o output.exe -r report.json
```

### Analyze Command
```bash
# Analyze file
python morpheus.py analyze -f sample.exe

# Save analysis
python morpheus.py analyze -f sample.exe -o analysis.json
```

### Train Classifier
```bash
# Train with your data
python morpheus.py train-classifier \
    -m data/malware \
    -b data/benign \
    -o models/pretrained/classifier.pkl
```

### Test Against Classifier
```bash
# Test file
python morpheus.py test -f mutated.exe -c models/pretrained/classifier.pkl
```

### Compare Files
```bash
# Compare original vs mutated
python morpheus.py compare -o original.exe -m mutated.exe
```

## 🎯 Usage Examples

### Example 1: Basic Workflow
```bash
# 1. Analyze original file
python morpheus.py analyze -f malware.exe

# 2. Mutate it
python morpheus.py mutate -i malware.exe -o mutated.exe -n 100

# 3. Analyze mutated file
python morpheus.py analyze -f mutated.exe

# 4. Compare them
python morpheus.py compare -o malware.exe -m mutated.exe
```

### Example 2: Training Workflow
```bash
# 1. Prepare data (place files in data/malware and data/benign)

# 2. Train classifier
python morpheus.py train-classifier \
    -m data/malware \
    -b data/benign \
    -o models/pretrained/my_classifier.pkl

# 3. Test a file
python morpheus.py test -f test.exe -c models/pretrained/my_classifier.pkl
```

### Example 3: Advanced Mutation
```bash
# Use specific techniques with RL
python morpheus.py mutate \
    -i malware.exe \
    -o mutated.exe \
    -n 200 \
    -t add_section,add_import,encrypt_section,polymorphic_mutation \
    --rl-model models/pretrained/rl_agent.pt \
    -r detailed_report.json
```

## 🐍 Python API Usage

### Example 1: Simple Mutation
```python
from core.mutator import MalwareMutator

# Initialize
mutator = MalwareMutator(use_rl=True, use_gan=True)

# Mutate
report = mutator.mutate(
    input_file='malware.exe',
    output_file='mutated.exe',
    iterations=100
)

print(f"Applied {report['mutation_count']} mutations")
```

### Example 2: PE Analysis
```python
from utils.pe_parser import PEParser

# Analyze
with PEParser('sample.exe') as parser:
    features = parser.extract_all_features()
    
    print(f"Entropy: {features['file_entropy']:.2f}")
    print(f"Sections: {features['section_count']}")
    print(f"Imports: {features['imported_dll_count']}")
    print(f"Suspicion Score: {features['suspicion_score']}")
```

### Example 3: Classifier
```python
from models.classifier import MalwareClassifier

# Load classifier
classifier = MalwareClassifier()
classifier.load('models/pretrained/classifier.pkl')

# Predict
prediction, confidence = classifier.predict('test.exe')

if prediction == 1:
    print(f"MALWARE detected with {confidence:.1%} confidence")
else:
    print(f"BENIGN with {confidence:.1%} confidence")
```

## ⚠️ Important Notes

### Safety First
- **Always use in a VM** - Never run on your main system
- **Disconnect network** - When handling malware samples
- **Legal compliance** - Only use on files you own or have permission to test
- **Ethical use** - For research and authorized testing only

### Getting Samples
- **Malware**: VirusShare, MalwareBazaar (requires registration)
- **Benign**: Windows system files, open-source software
- **Testing**: Create your own test executables

### Performance Tips
- Start with low iterations (50-100) for testing
- Use RL for better mutation selection
- Train classifier on your own dataset for best results
- GPU recommended for training (but CPU works too)

## 🔧 Troubleshooting

### "Failed to parse PE file"
- Ensure file is a valid PE executable
- Check file is not corrupted
- Try with a different file

### "Module not found"
- Run: `pip install -r requirements.txt`
- Ensure you're in the correct directory
- Check virtual environment is activated

### "Classifier not trained"
- Train classifier first: `python morpheus.py train-classifier ...`
- Or load pre-trained model

### Low mutation success rate
- Some mutations may fail on certain files
- This is normal - the tool tries multiple techniques
- Increase iterations for better results

## 📚 Documentation

- **README.md** - Main documentation
- **QUICKSTART.md** - Quick start guide
- **FEATURES.md** - Complete feature list
- **PROJECT_STRUCTURE.md** - Code organization
- **PROJECT_COMPLETE.md** - Project summary
- **LICENSE** - License and disclaimer

## 🎓 Learning Resources

1. **Start with examples/** - See working code
2. **Read the docs** - Understand the concepts
3. **Experiment** - Try different techniques
4. **Extend** - Add your own mutations
5. **Share** - Contribute back (ethically!)

## 🌟 What's Next?

1. ✅ Install and test
2. ✅ Run examples
3. ✅ Try basic mutations
4. ✅ Collect training data
5. ✅ Train your models
6. ✅ Experiment with techniques
7. ✅ Extend with custom mutations
8. ✅ Use for ethical research!

---

**Happy (Ethical) Hacking! 🛡️**

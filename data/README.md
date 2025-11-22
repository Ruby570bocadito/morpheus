# Data Directory

## Structure

```
data/
├── samples/      # Sample PE files for testing
├── malware/      # Malware samples for training (⚠️ Handle with care!)
├── benign/       # Benign executables for training
├── training/     # Training datasets
└── results/      # Mutation results
```

## ⚠️ Important Notes

### Malware Samples
- **NEVER** run malware samples outside a VM
- Use only in isolated, controlled environments
- Obtain samples from legitimate sources (e.g., malware repositories for researchers)
- Follow all legal and ethical guidelines

### Benign Samples
- Use legitimate Windows executables
- Common sources: Windows System32, Program Files
- Ensure you have rights to use these files

### Best Practices
1. Always work in a virtual machine
2. Disconnect from network when handling malware
3. Use proper malware handling procedures
4. Keep samples encrypted when not in use
5. Follow your organization's security policies

## Getting Samples

### For Research/Education:
- **VirusShare**: https://virusshare.com/ (requires registration)
- **MalwareBazaar**: https://bazaar.abuse.ch/
- **Benign samples**: Windows system files, open-source software

### For Testing:
- Create your own test executables
- Use EICAR test file for AV testing
- Generate synthetic samples

## Usage

```bash
# Train classifier
python morpheus.py train-classifier \
    --malware-dir data/malware \
    --benign-dir data/benign \
    --output models/classifier.pkl

# Mutate samples
python morpheus.py mutate \
    --input data/samples/test.exe \
    --output data/results/mutated.exe
```

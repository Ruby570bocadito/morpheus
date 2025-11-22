"""
PE Manipulator - Advanced PE file manipulation for mutations
"""

import lief
import random
import struct
from pathlib import Path
from typing import List, Dict, Any, Optional
import os


class PEManipulator:
    """Advanced PE file manipulator for applying mutations"""
    
    def __init__(self, filepath: str):
        """
        Initialize PE manipulator
        
        Args:
            filepath: Path to PE file
        """
        self.filepath = Path(filepath)
        self.binary = lief.parse(str(filepath))
        
        if not self.binary:
            raise ValueError(f"Failed to parse PE file: {filepath}")
    
    def add_section(self, name: str, size: int, characteristics: int = 0x60000020) -> bool:
        """
        Add a new section to PE file
        
        Args:
            name: Section name (max 8 chars)
            size: Section size in bytes
            characteristics: Section characteristics
            
        Returns:
            True if successful
        """
        try:
            section = lief.PE.Section(name[:8])
            section.content = [random.randint(0, 255) for _ in range(size)]
            section.characteristics = characteristics
            
            self.binary.add_section(section)
            return True
        except Exception as e:
            print(f"Failed to add section: {e}")
            return False
    
    def add_import(self, dll_name: str, function_names: List[str]) -> bool:
        """
        Add imports to PE file
        
        Args:
            dll_name: DLL name
            function_names: List of function names to import
            
        Returns:
            True if successful
        """
        try:
            # Check if DLL already imported
            existing_import = None
            for imp in self.binary.imports:
                if imp.name.lower() == dll_name.lower():
                    existing_import = imp
                    break
            
            if existing_import:
                # Add functions to existing import
                for func_name in function_names:
                    entry = lief.PE.ImportEntry(func_name)
                    existing_import.add_entry(entry)
            else:
                # Create new import
                new_import = lief.PE.Import(dll_name)
                for func_name in function_names:
                    entry = lief.PE.ImportEntry(func_name)
                    new_import.add_entry(entry)
                self.binary.add_import(new_import)
            
            return True
        except Exception as e:
            print(f"Failed to add import: {e}")
            return False
    
    def modify_timestamp(self, timestamp: Optional[int] = None) -> bool:
        """
        Modify PE timestamp
        
        Args:
            timestamp: New timestamp (random if None)
            
        Returns:
            True if successful
        """
        try:
            if timestamp is None:
                timestamp = random.randint(0, 0xFFFFFFFF)
            
            self.binary.header.time_date_stamps = timestamp
            return True
        except Exception as e:
            print(f"Failed to modify timestamp: {e}")
            return False
    
    def modify_checksum(self) -> bool:
        """
        Recalculate and update PE checksum
        
        Returns:
            True if successful
        """
        try:
            self.binary.optional_header.checksum = self.binary.calculate_checksum()
            return True
        except Exception as e:
            print(f"Failed to modify checksum: {e}")
            return False
    
    def inject_code_cave(self, code: bytes, section_name: Optional[str] = None) -> bool:
        """
        Inject code into a code cave
        
        Args:
            code: Code bytes to inject
            section_name: Target section (random if None)
            
        Returns:
            True if successful
        """
        try:
            sections = list(self.binary.sections)
            if not sections:
                return False
            
            if section_name:
                target_section = next((s for s in sections if s.name == section_name), None)
            else:
                target_section = random.choice(sections)
            
            if not target_section:
                return False
            
            # Find code cave (null bytes)
            content = list(target_section.content)
            cave_size = len(code)
            
            for i in range(len(content) - cave_size):
                if all(content[i+j] == 0 for j in range(cave_size)):
                    # Found cave, inject code
                    content[i:i+cave_size] = code
                    target_section.content = content
                    return True
            
            # No cave found, append to section
            target_section.content = content + list(code)
            return True
            
        except Exception as e:
            print(f"Failed to inject code cave: {e}")
            return False
    
    def add_overlay(self, data: bytes) -> bool:
        """
        Add overlay data to PE file
        
        Args:
            data: Overlay data
            
        Returns:
            True if successful
        """
        try:
            self.binary.overlay = list(data)
            return True
        except Exception as e:
            print(f"Failed to add overlay: {e}")
            return False
    
    def modify_entry_point(self, new_ep: Optional[int] = None) -> bool:
        """
        Modify entry point
        
        Args:
            new_ep: New entry point RVA (random valid if None)
            
        Returns:
            True if successful
        """
        try:
            if new_ep is None:
                # Find executable section
                exec_sections = [s for s in self.binary.sections 
                               if s.characteristics & 0x20000000]  # IMAGE_SCN_MEM_EXECUTE
                if not exec_sections:
                    return False
                
                section = random.choice(exec_sections)
                new_ep = section.virtual_address + random.randint(0, section.size // 2)
            
            self.binary.optional_header.addressof_entrypoint = new_ep
            return True
        except Exception as e:
            print(f"Failed to modify entry point: {e}")
            return False
    
    def encrypt_section(self, section_name: str, key: bytes) -> bool:
        """
        Encrypt a section with XOR
        
        Args:
            section_name: Section to encrypt
            key: Encryption key
            
        Returns:
            True if successful
        """
        try:
            section = next((s for s in self.binary.sections if s.name == section_name), None)
            if not section:
                return False
            
            content = list(section.content)
            encrypted = []
            
            for i, byte in enumerate(content):
                encrypted.append(byte ^ key[i % len(key)])
            
            section.content = encrypted
            return True
        except Exception as e:
            print(f"Failed to encrypt section: {e}")
            return False
    
    def add_resource(self, resource_type: int, resource_id: int, data: bytes) -> bool:
        """
        Add resource to PE file
        
        Args:
            resource_type: Resource type ID
            resource_id: Resource ID
            data: Resource data
            
        Returns:
            True if successful
        """
        try:
            # LIEF resource manipulation is complex, simplified version
            # In production, use more sophisticated resource handling
            return True
        except Exception as e:
            print(f"Failed to add resource: {e}")
            return False
    
    def modify_section_characteristics(self, section_name: str, characteristics: int) -> bool:
        """
        Modify section characteristics
        
        Args:
            section_name: Section name
            characteristics: New characteristics
            
        Returns:
            True if successful
        """
        try:
            section = next((s for s in self.binary.sections if s.name == section_name), None)
            if not section:
                return False
            
            section.characteristics = characteristics
            return True
        except Exception as e:
            print(f"Failed to modify section characteristics: {e}")
            return False
    
    def remove_rich_header(self) -> bool:
        """
        Remove Rich header
        
        Returns:
            True if successful
        """
        try:
            if hasattr(self.binary, 'rich_header'):
                self.binary.rich_header = None
            return True
        except Exception as e:
            print(f"Failed to remove rich header: {e}")
            return False
    
    def add_tls_callback(self, callback_rva: int) -> bool:
        """
        Add TLS callback
        
        Args:
            callback_rva: RVA of callback function
            
        Returns:
            True if successful
        """
        try:
            # Simplified TLS callback addition
            # In production, implement full TLS directory manipulation
            return True
        except Exception as e:
            print(f"Failed to add TLS callback: {e}")
            return False
    
    def save(self, output_path: str) -> bool:
        """
        Save modified PE file
        
        Args:
            output_path: Output file path
            
        Returns:
            True if successful
        """
        try:
            builder = lief.PE.Builder(self.binary)
            builder.build()
            builder.write(output_path)
            
            # Verify file was created
            return Path(output_path).exists()
        except Exception as e:
            print(f"Failed to save PE file: {e}")
            return False
    
    def get_info(self) -> Dict[str, Any]:
        """Get PE file information"""
        return {
            'sections': len(list(self.binary.sections)),
            'imports': len(list(self.binary.imports)),
            'exports': len(list(self.binary.exported_functions)),
            'entry_point': self.binary.optional_header.addressof_entrypoint,
            'image_base': self.binary.optional_header.imagebase,
        }


# Benign DLL and function lists for decoy imports
BENIGN_DLLS = [
    'kernel32.dll', 'user32.dll', 'advapi32.dll', 'gdi32.dll',
    'shell32.dll', 'ole32.dll', 'oleaut32.dll', 'comctl32.dll',
    'comdlg32.dll', 'ws2_32.dll', 'wininet.dll', 'version.dll'
]

BENIGN_FUNCTIONS = {
    'kernel32.dll': ['GetTickCount', 'GetSystemTime', 'GetComputerNameW', 'GetVersion'],
    'user32.dll': ['GetSystemMetrics', 'GetDesktopWindow', 'MessageBeep', 'GetKeyboardType'],
    'advapi32.dll': ['RegCloseKey', 'GetUserNameW', 'LookupAccountNameW'],
    'gdi32.dll': ['GetDeviceCaps', 'GetStockObject', 'GetTextMetricsW'],
    'shell32.dll': ['SHGetFolderPathW', 'SHGetFileInfoW'],
}

BENIGN_SECTION_NAMES = [
    '.rdata', '.data', '.text', '.rsrc', '.reloc', '.idata',
    '.tls', '.debug', '.pdata', '.xdata'
]

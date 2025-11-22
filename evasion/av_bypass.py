"""
Anti-AV Evasion Techniques
"""

import random
from typing import List, Dict, Any


class AVBypass:
    """Anti-AV evasion techniques"""
    
    @staticmethod
    def add_entropy_padding(size: int = 1024) -> bytes:
        """
        Add high-entropy padding to confuse entropy-based detection
        
        Args:
            size: Size of padding
            
        Returns:
            Random bytes
        """
        return bytes([random.randint(0, 255) for _ in range(size)])
    
    @staticmethod
    def generate_decoy_strings() -> List[str]:
        """Generate benign-looking strings"""
        decoy_strings = [
            "Microsoft Corporation",
            "Copyright (C) Microsoft Corp.",
            "Windows Operating System",
            "System32",
            "Program Files",
            "Application Data",
            "HKEY_LOCAL_MACHINE",
            "SOFTWARE\\Microsoft\\Windows",
        ]
        return random.sample(decoy_strings, min(5, len(decoy_strings)))
    
    @staticmethod
    def obfuscate_api_calls() -> Dict[str, int]:
        """
        Generate API hash table for dynamic resolution
        
        Returns:
            Dictionary of API hashes
        """
        apis = [
            'VirtualAlloc',
            'VirtualProtect',
            'CreateThread',
            'WaitForSingleObject',
        ]
        
        hashes = {}
        for api in apis:
            # Simple hash (in production, use proper hashing)
            hash_val = sum(ord(c) for c in api) % 0xFFFFFFFF
            hashes[api] = hash_val
        
        return hashes
    
    @staticmethod
    def generate_junk_code(size: int = 100) -> bytes:
        """
        Generate junk code (NOPs, harmless instructions)
        
        Args:
            size: Size of junk code
            
        Returns:
            Junk code bytes
        """
        junk_instructions = [
            b'\x90',  # NOP
            b'\x66\x90',  # 2-byte NOP
            b'\x0F\x1F\x00',  # 3-byte NOP
            b'\x40',  # INC EAX
            b'\x48',  # DEC EAX
        ]
        
        junk = b''
        while len(junk) < size:
            junk += random.choice(junk_instructions)
        
        return junk[:size]
    
    @staticmethod
    def create_fake_certificate_info() -> Dict[str, str]:
        """Create fake certificate information"""
        return {
            'issuer': 'Microsoft Code Signing PCA',
            'subject': 'Microsoft Corporation',
            'serial': ''.join([str(random.randint(0, 9)) for _ in range(16)]),
        }


class SandboxEvasion:
    """Anti-sandbox techniques"""
    
    @staticmethod
    def generate_sleep_code() -> bytes:
        """
        Generate code for time-based evasion
        
        Returns:
            Sleep code bytes
        """
        # In real implementation, this would be actual assembly
        # For now, return placeholder
        return b'\x90' * 10
    
    @staticmethod
    def check_vm_artifacts() -> List[str]:
        """List of VM artifacts to check"""
        return [
            'VBOX',
            'VMware',
            'QEMU',
            'VirtualBox',
            'Xen',
        ]
    
    @staticmethod
    def generate_anti_debug_checks() -> List[str]:
        """List of anti-debug checks"""
        return [
            'IsDebuggerPresent',
            'CheckRemoteDebuggerPresent',
            'NtQueryInformationProcess',
            'OutputDebugString',
        ]


class AntiDebug:
    """Anti-debugging techniques"""
    
    @staticmethod
    def generate_peb_check() -> bytes:
        """Generate PEB BeingDebugged check"""
        # Simplified - in production, use actual assembly
        return b'\x90' * 20
    
    @staticmethod
    def generate_timing_check() -> bytes:
        """Generate timing-based anti-debug"""
        return b'\x90' * 20
    
    @staticmethod
    def generate_exception_check() -> bytes:
        """Generate exception-based anti-debug"""
        return b'\x90' * 20

"""
PE Parser - Advanced PE file analysis and feature extraction
"""

import pefile
import hashlib
import math
from pathlib import Path
from typing import Dict, List, Any, Optional
import struct


class PEParser:
    """Advanced PE file parser with feature extraction capabilities"""
    
    def __init__(self, filepath: str):
        """
        Initialize PE parser
        
        Args:
            filepath: Path to PE file
        """
        self.filepath = Path(filepath)
        self.pe = None
        self.features = {}
        
        try:
            self.pe = pefile.PE(str(filepath))
        except Exception as e:
            raise ValueError(f"Failed to parse PE file: {e}")
    
    def extract_all_features(self) -> Dict[str, Any]:
        """Extract all features from PE file"""
        self.features = {
            **self.get_basic_info(),
            **self.get_header_features(),
            **self.get_section_features(),
            **self.get_import_features(),
            **self.get_export_features(),
            **self.get_entropy_features(),
            **self.get_resource_features(),
            **self.get_suspicious_indicators()
        }
        return self.features
    
    def get_basic_info(self) -> Dict[str, Any]:
        """Get basic PE information"""
        return {
            'file_size': self.filepath.stat().st_size,
            'md5': self._calculate_hash('md5'),
            'sha1': self._calculate_hash('sha1'),
            'sha256': self._calculate_hash('sha256'),
            'is_dll': self.pe.is_dll(),
            'is_exe': self.pe.is_exe(),
            'is_driver': self.pe.is_driver(),
        }
    
    def get_header_features(self) -> Dict[str, Any]:
        """Extract PE header features"""
        dos_header = self.pe.DOS_HEADER
        nt_headers = self.pe.NT_HEADERS
        file_header = self.pe.FILE_HEADER
        optional_header = self.pe.OPTIONAL_HEADER
        
        return {
            'e_magic': dos_header.e_magic,
            'e_lfanew': dos_header.e_lfanew,
            'machine': file_header.Machine,
            'number_of_sections': file_header.NumberOfSections,
            'timestamp': file_header.TimeDateStamp,
            'characteristics': file_header.Characteristics,
            'size_of_optional_header': file_header.SizeOfOptionalHeader,
            'magic': optional_header.Magic,
            'major_linker_version': optional_header.MajorLinkerVersion,
            'minor_linker_version': optional_header.MinorLinkerVersion,
            'size_of_code': optional_header.SizeOfCode,
            'size_of_initialized_data': optional_header.SizeOfInitializedData,
            'size_of_uninitialized_data': optional_header.SizeOfUninitializedData,
            'address_of_entry_point': optional_header.AddressOfEntryPoint,
            'base_of_code': optional_header.BaseOfCode,
            'image_base': optional_header.ImageBase,
            'section_alignment': optional_header.SectionAlignment,
            'file_alignment': optional_header.FileAlignment,
            'size_of_image': optional_header.SizeOfImage,
            'size_of_headers': optional_header.SizeOfHeaders,
            'checksum': optional_header.CheckSum,
            'subsystem': optional_header.Subsystem,
            'dll_characteristics': optional_header.DllCharacteristics,
        }
    
    def get_section_features(self) -> Dict[str, Any]:
        """Extract section-related features"""
        sections = []
        total_virtual_size = 0
        total_raw_size = 0
        
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            virtual_size = section.Misc_VirtualSize
            raw_size = section.SizeOfRawData
            
            sections.append({
                'name': section_name,
                'virtual_address': section.VirtualAddress,
                'virtual_size': virtual_size,
                'raw_size': raw_size,
                'characteristics': section.Characteristics,
                'entropy': self._calculate_section_entropy(section),
            })
            
            total_virtual_size += virtual_size
            total_raw_size += raw_size
        
        return {
            'sections': sections,
            'section_count': len(sections),
            'total_virtual_size': total_virtual_size,
            'total_raw_size': total_raw_size,
            'avg_section_entropy': sum(s['entropy'] for s in sections) / len(sections) if sections else 0,
        }
    
    def get_import_features(self) -> Dict[str, Any]:
        """Extract import table features"""
        imports = []
        suspicious_imports = []
        
        suspicious_apis = [
            'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
            'CreateRemoteThread', 'LoadLibrary', 'GetProcAddress',
            'WinExec', 'ShellExecute', 'URLDownloadToFile',
            'InternetOpen', 'InternetReadFile', 'CreateProcess',
            'RegSetValue', 'RegCreateKey', 'CryptEncrypt'
        ]
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                functions = []
                
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        functions.append(func_name)
                        
                        if func_name in suspicious_apis:
                            suspicious_imports.append(f"{dll_name}:{func_name}")
                
                imports.append({
                    'dll': dll_name,
                    'functions': functions,
                    'function_count': len(functions)
                })
        
        return {
            'imports': imports,
            'imported_dll_count': len(imports),
            'total_imported_functions': sum(i['function_count'] for i in imports),
            'suspicious_imports': suspicious_imports,
            'suspicious_import_count': len(suspicious_imports),
        }
    
    def get_export_features(self) -> Dict[str, Any]:
        """Extract export table features"""
        exports = []
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append({
                    'name': exp.name.decode('utf-8', errors='ignore') if exp.name else None,
                    'ordinal': exp.ordinal,
                    'address': exp.address
                })
        
        return {
            'exports': exports,
            'export_count': len(exports),
        }
    
    def get_entropy_features(self) -> Dict[str, Any]:
        """Calculate entropy-based features"""
        with open(self.filepath, 'rb') as f:
            data = f.read()
        
        return {
            'file_entropy': self._calculate_entropy(data),
            'packed_probability': self._estimate_packing_probability(),
        }
    
    def get_resource_features(self) -> Dict[str, Any]:
        """Extract resource section features"""
        resources = []
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = self.pe.get_data(
                                    resource_lang.data.struct.OffsetToData,
                                    resource_lang.data.struct.Size
                                )
                                resources.append({
                                    'type': resource_type.id,
                                    'id': resource_id.id,
                                    'size': resource_lang.data.struct.Size,
                                    'entropy': self._calculate_entropy(data)
                                })
        
        return {
            'resources': resources,
            'resource_count': len(resources),
        }
    
    def get_suspicious_indicators(self) -> Dict[str, Any]:
        """Detect suspicious indicators"""
        indicators = []
        
        # Check for suspicious section names
        suspicious_section_names = ['.upx', '.aspack', '.adata', '.boom']
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            if any(sus in section_name.lower() for sus in suspicious_section_names):
                indicators.append(f"Suspicious section name: {section_name}")
        
        # Check for abnormal entry point
        if hasattr(self.pe, 'OPTIONAL_HEADER'):
            ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            for section in self.pe.sections:
                if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                    section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    if section_name not in ['.text', 'CODE']:
                        indicators.append(f"Entry point in unusual section: {section_name}")
        
        # Check for high entropy (possible packing)
        if self.features.get('file_entropy', 0) > 7.0:
            indicators.append("High entropy detected (possible packing)")
        
        # Check for TLS callbacks
        if hasattr(self.pe, 'DIRECTORY_ENTRY_TLS'):
            indicators.append("TLS callbacks present")
        
        return {
            'suspicious_indicators': indicators,
            'suspicion_score': len(indicators),
        }
    
    def _calculate_hash(self, algorithm: str) -> str:
        """Calculate file hash"""
        hash_obj = hashlib.new(algorithm)
        with open(self.filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy
    
    def _calculate_section_entropy(self, section) -> float:
        """Calculate entropy of a PE section"""
        data = section.get_data()
        return self._calculate_entropy(data)
    
    def _estimate_packing_probability(self) -> float:
        """Estimate probability that file is packed"""
        score = 0.0
        
        # High entropy indicates packing
        if 'file_entropy' in self.features:
            if self.features['file_entropy'] > 7.0:
                score += 0.4
            elif self.features['file_entropy'] > 6.5:
                score += 0.2
        
        # Low import count indicates packing
        if 'total_imported_functions' in self.features:
            if self.features['total_imported_functions'] < 10:
                score += 0.3
        
        # Suspicious section names
        if 'suspicious_indicators' in self.features:
            for indicator in self.features['suspicious_indicators']:
                if 'section name' in indicator.lower():
                    score += 0.3
                    break
        
        return min(score, 1.0)
    
    def close(self):
        """Close PE file"""
        if self.pe:
            self.pe.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def analyze_pe_file(filepath: str) -> Dict[str, Any]:
    """
    Convenience function to analyze a PE file
    
    Args:
        filepath: Path to PE file
        
    Returns:
        Dictionary of extracted features
    """
    with PEParser(filepath) as parser:
        return parser.extract_all_features()

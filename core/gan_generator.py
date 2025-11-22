"""
GAN Generator - Generates realistic PE components using Wasserstein GAN
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from typing import List, Tuple, Dict


class Generator(nn.Module):
    """Generator network for creating PE components"""
    
    def __init__(self, latent_dim: int = 100, output_dim: int = 256):
        super(Generator, self).__init__()
        
        self.model = nn.Sequential(
            nn.Linear(latent_dim, 256),
            nn.LeakyReLU(0.2),
            nn.BatchNorm1d(256),
            
            nn.Linear(256, 512),
            nn.LeakyReLU(0.2),
            nn.BatchNorm1d(512),
            
            nn.Linear(512, 1024),
            nn.LeakyReLU(0.2),
            nn.BatchNorm1d(1024),
            
            nn.Linear(1024, output_dim),
            nn.Tanh()
        )
    
    def forward(self, z):
        return self.model(z)


class Discriminator(nn.Module):
    """Discriminator network for evaluating PE components"""
    
    def __init__(self, input_dim: int = 256):
        super(Discriminator, self).__init__()
        
        self.model = nn.Sequential(
            nn.Linear(input_dim, 1024),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.3),
            
            nn.Linear(1024, 512),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.3),
            
            nn.Linear(512, 256),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.3),
            
            nn.Linear(256, 1)
        )
    
    def forward(self, x):
        return self.model(x)


class WGAN:
    """Wasserstein GAN for generating PE components"""
    
    def __init__(self, latent_dim: int = 100, output_dim: int = 256,
                 lr: float = 1e-4, n_critic: int = 5, clip_value: float = 0.01):
        """
        Initialize WGAN
        
        Args:
            latent_dim: Dimension of latent space
            output_dim: Dimension of output
            lr: Learning rate
            n_critic: Number of critic updates per generator update
            clip_value: Weight clipping value
        """
        self.latent_dim = latent_dim
        self.output_dim = output_dim
        self.n_critic = n_critic
        self.clip_value = clip_value
        
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        self.generator = Generator(latent_dim, output_dim).to(self.device)
        self.discriminator = Discriminator(output_dim).to(self.device)
        
        self.g_optimizer = optim.RMSprop(self.generator.parameters(), lr=lr)
        self.d_optimizer = optim.RMSprop(self.discriminator.parameters(), lr=lr)
    
    def train_step(self, real_data: torch.Tensor) -> Tuple[float, float]:
        """
        Single training step
        
        Args:
            real_data: Real PE component data
            
        Returns:
            Tuple of (discriminator_loss, generator_loss)
        """
        batch_size = real_data.size(0)
        real_data = real_data.to(self.device)
        
        # Train Discriminator
        for _ in range(self.n_critic):
            self.d_optimizer.zero_grad()
            
            # Real data
            real_validity = self.discriminator(real_data)
            
            # Fake data
            z = torch.randn(batch_size, self.latent_dim).to(self.device)
            fake_data = self.generator(z).detach()
            fake_validity = self.discriminator(fake_data)
            
            # Wasserstein loss
            d_loss = -torch.mean(real_validity) + torch.mean(fake_validity)
            
            d_loss.backward()
            self.d_optimizer.step()
            
            # Clip weights
            for p in self.discriminator.parameters():
                p.data.clamp_(-self.clip_value, self.clip_value)
        
        # Train Generator
        self.g_optimizer.zero_grad()
        
        z = torch.randn(batch_size, self.latent_dim).to(self.device)
        fake_data = self.generator(z)
        fake_validity = self.discriminator(fake_data)
        
        g_loss = -torch.mean(fake_validity)
        
        g_loss.backward()
        self.g_optimizer.step()
        
        return d_loss.item(), g_loss.item()
    
    def generate(self, n_samples: int = 1) -> np.ndarray:
        """
        Generate samples
        
        Args:
            n_samples: Number of samples to generate
            
        Returns:
            Generated samples
        """
        self.generator.eval()
        with torch.no_grad():
            z = torch.randn(n_samples, self.latent_dim).to(self.device)
            samples = self.generator(z)
        self.generator.train()
        
        return samples.cpu().numpy()
    
    def save(self, filepath: str):
        """Save models"""
        torch.save({
            'generator_state_dict': self.generator.state_dict(),
            'discriminator_state_dict': self.discriminator.state_dict(),
            'g_optimizer_state_dict': self.g_optimizer.state_dict(),
            'd_optimizer_state_dict': self.d_optimizer.state_dict(),
        }, filepath)
    
    def load(self, filepath: str):
        """Load models"""
        checkpoint = torch.load(filepath, map_location=self.device)
        self.generator.load_state_dict(checkpoint['generator_state_dict'])
        self.discriminator.load_state_dict(checkpoint['discriminator_state_dict'])
        self.g_optimizer.load_state_dict(checkpoint['g_optimizer_state_dict'])
        self.d_optimizer.load_state_dict(checkpoint['d_optimizer_state_dict'])


class GANGenerator:
    """High-level GAN generator for PE components"""
    
    def __init__(self):
        """Initialize GAN generator"""
        self.section_gan = WGAN(latent_dim=100, output_dim=256)
        self.import_gan = WGAN(latent_dim=100, output_dim=128)
    
    def generate_section_data(self, size: int = 1024) -> bytes:
        """
        Generate realistic section data
        
        Args:
            size: Size of section data
            
        Returns:
            Section data bytes
        """
        # Generate using GAN
        samples = self.section_gan.generate(n_samples=1)[0]
        
        # Convert to bytes
        # Denormalize from [-1, 1] to [0, 255]
        data = ((samples + 1) * 127.5).astype(np.uint8)
        
        # Repeat to fill size
        while len(data) < size:
            data = np.concatenate([data, data])
        
        return bytes(data[:size])
    
    def generate_import_names(self, dll_name: str, count: int = 5) -> List[str]:
        """
        Generate realistic import function names
        
        Args:
            dll_name: DLL name
            count: Number of functions to generate
            
        Returns:
            List of function names
        """
        # Predefined realistic function names by DLL
        common_functions = {
            'kernel32.dll': [
                'GetSystemTime', 'GetTickCount', 'GetComputerNameW',
                'GetVersion', 'GetSystemInfo', 'GetCurrentProcess',
                'GetModuleHandleW', 'GetProcAddress', 'LoadLibraryW',
                'Sleep', 'GetLastError', 'SetLastError'
            ],
            'user32.dll': [
                'GetSystemMetrics', 'GetDesktopWindow', 'MessageBeep',
                'GetKeyboardType', 'GetCursorPos', 'SetCursorPos',
                'ShowWindow', 'GetWindowRect', 'GetClientRect'
            ],
            'advapi32.dll': [
                'RegCloseKey', 'GetUserNameW', 'LookupAccountNameW',
                'OpenProcessToken', 'GetTokenInformation'
            ],
            'ws2_32.dll': [
                'WSAStartup', 'WSACleanup', 'socket', 'connect',
                'send', 'recv', 'closesocket', 'gethostbyname'
            ]
        }
        
        # Get functions for this DLL or use generic ones
        functions = common_functions.get(dll_name.lower(), common_functions['kernel32.dll'])
        
        # Randomly select functions
        import random
        selected = random.sample(functions, min(count, len(functions)))
        
        return selected
    
    def generate_section_name(self) -> str:
        """
        Generate realistic section name
        
        Returns:
            Section name
        """
        common_names = [
            '.text', '.data', '.rdata', '.rsrc', '.reloc',
            '.idata', '.edata', '.tls', '.debug', '.pdata'
        ]
        
        import random
        return random.choice(common_names)
    
    def train_section_gan(self, training_data: np.ndarray, epochs: int = 100):
        """
        Train section GAN
        
        Args:
            training_data: Training data (section contents)
            epochs: Number of training epochs
        """
        batch_size = 32
        
        for epoch in range(epochs):
            # Sample batch
            idx = np.random.randint(0, training_data.shape[0], batch_size)
            real_batch = torch.FloatTensor(training_data[idx])
            
            # Train
            d_loss, g_loss = self.section_gan.train_step(real_batch)
            
            if epoch % 10 == 0:
                print(f"Epoch {epoch}/{epochs} - D Loss: {d_loss:.4f}, G Loss: {g_loss:.4f}")
    
    def save(self, section_path: str, import_path: str):
        """Save GAN models"""
        self.section_gan.save(section_path)
        self.import_gan.save(import_path)
    
    def load(self, section_path: str, import_path: str):
        """Load GAN models"""
        self.section_gan.load(section_path)
        self.import_gan.load(import_path)

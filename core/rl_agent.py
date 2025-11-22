"""
Reinforcement Learning Agent - PPO-based agent for intelligent malware mutation
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from typing import List, Tuple, Dict, Any
from collections import deque
import random


class PolicyNetwork(nn.Module):
    """Policy network for PPO agent"""
    
    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 256):
        super(PolicyNetwork, self).__init__()
        
        self.actor = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, action_dim),
            nn.Softmax(dim=-1)
        )
        
        self.critic = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, 1)
        )
    
    def forward(self, state):
        """Forward pass"""
        action_probs = self.actor(state)
        state_value = self.critic(state)
        return action_probs, state_value
    
    def get_action(self, state):
        """Sample action from policy"""
        action_probs, state_value = self.forward(state)
        dist = torch.distributions.Categorical(action_probs)
        action = dist.sample()
        action_log_prob = dist.log_prob(action)
        
        return action.item(), action_log_prob, state_value


class PPOAgent:
    """Proximal Policy Optimization agent for malware mutation"""
    
    # Action space: different mutation techniques
    ACTIONS = [
        'add_section',
        'add_import',
        'modify_timestamp',
        'inject_code_cave',
        'add_overlay',
        'modify_entry_point',
        'encrypt_section',
        'add_resource',
        'modify_section_characteristics',
        'remove_rich_header',
        'add_tls_callback',
        'modify_checksum',
        'add_padding',
        'obfuscate_strings',
        'polymorphic_mutation'
    ]
    
    def __init__(self, state_dim: int = 200, learning_rate: float = 3e-4,
                 gamma: float = 0.99, epsilon: float = 0.2, epochs: int = 10):
        """
        Initialize PPO agent
        
        Args:
            state_dim: Dimension of state space
            learning_rate: Learning rate
            gamma: Discount factor
            epsilon: PPO clip parameter
            epochs: Number of optimization epochs
        """
        self.state_dim = state_dim
        self.action_dim = len(self.ACTIONS)
        self.gamma = gamma
        self.epsilon = epsilon
        self.epochs = epochs
        
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        self.policy = PolicyNetwork(state_dim, self.action_dim).to(self.device)
        self.optimizer = optim.Adam(self.policy.parameters(), lr=learning_rate)
        
        self.memory = deque(maxlen=10000)
        
    def state_to_tensor(self, state: Dict[str, Any]) -> torch.Tensor:
        """
        Convert PE features to state tensor
        
        Args:
            state: Dictionary of PE features
            
        Returns:
            State tensor
        """
        # Extract relevant features and normalize
        features = []
        
        # Basic features
        features.append(state.get('file_size', 0) / 1e6)  # Normalize to MB
        features.append(state.get('number_of_sections', 0) / 10)
        features.append(state.get('section_count', 0) / 10)
        features.append(state.get('imported_dll_count', 0) / 20)
        features.append(state.get('total_imported_functions', 0) / 100)
        features.append(state.get('export_count', 0) / 50)
        features.append(state.get('resource_count', 0) / 20)
        features.append(state.get('file_entropy', 0) / 8)
        features.append(state.get('avg_section_entropy', 0) / 8)
        features.append(state.get('packed_probability', 0))
        features.append(state.get('suspicion_score', 0) / 10)
        features.append(state.get('suspicious_import_count', 0) / 10)
        
        # Header features
        features.append(state.get('size_of_code', 0) / 1e6)
        features.append(state.get('size_of_initialized_data', 0) / 1e6)
        features.append(state.get('size_of_image', 0) / 1e6)
        features.append(state.get('size_of_headers', 0) / 1000)
        
        # Section features (aggregate)
        sections = state.get('sections', [])
        if sections:
            avg_virtual_size = np.mean([s.get('virtual_size', 0) for s in sections]) / 1e6
            avg_raw_size = np.mean([s.get('raw_size', 0) for s in sections]) / 1e6
            features.extend([avg_virtual_size, avg_raw_size])
        else:
            features.extend([0, 0])
        
        # Pad to state_dim
        while len(features) < self.state_dim:
            features.append(0)
        
        features = features[:self.state_dim]
        
        return torch.FloatTensor(features).to(self.device)
    
    def select_action(self, state: Dict[str, Any]) -> Tuple[int, str, float, float]:
        """
        Select action using current policy
        
        Args:
            state: Current state (PE features)
            
        Returns:
            Tuple of (action_idx, action_name, log_prob, state_value)
        """
        state_tensor = self.state_to_tensor(state).unsqueeze(0)
        
        with torch.no_grad():
            action_idx, log_prob, state_value = self.policy.get_action(state_tensor)
        
        action_name = self.ACTIONS[action_idx]
        
        return action_idx, action_name, log_prob.item(), state_value.item()
    
    def store_transition(self, state, action, reward, next_state, done, log_prob, value):
        """Store transition in memory"""
        self.memory.append({
            'state': state,
            'action': action,
            'reward': reward,
            'next_state': next_state,
            'done': done,
            'log_prob': log_prob,
            'value': value
        })
    
    def compute_returns(self, rewards: List[float], dones: List[bool]) -> List[float]:
        """Compute discounted returns"""
        returns = []
        R = 0
        
        for reward, done in zip(reversed(rewards), reversed(dones)):
            if done:
                R = 0
            R = reward + self.gamma * R
            returns.insert(0, R)
        
        return returns
    
    def update(self, batch_size: int = 64):
        """
        Update policy using PPO
        
        Args:
            batch_size: Batch size for training
        """
        if len(self.memory) < batch_size:
            return
        
        # Sample batch
        batch = random.sample(self.memory, batch_size)
        
        states = torch.stack([self.state_to_tensor(t['state']) for t in batch])
        actions = torch.LongTensor([t['action'] for t in batch]).to(self.device)
        old_log_probs = torch.FloatTensor([t['log_prob'] for t in batch]).to(self.device)
        rewards = [t['reward'] for t in batch]
        dones = [t['done'] for t in batch]
        
        # Compute returns
        returns = self.compute_returns(rewards, dones)
        returns = torch.FloatTensor(returns).to(self.device)
        
        # Normalize returns
        returns = (returns - returns.mean()) / (returns.std() + 1e-8)
        
        # PPO update
        for _ in range(self.epochs):
            # Get current policy
            action_probs, state_values = self.policy(states)
            state_values = state_values.squeeze()
            
            # Compute advantages
            advantages = returns - state_values.detach()
            
            # Get log probs for actions
            dist = torch.distributions.Categorical(action_probs)
            new_log_probs = dist.log_prob(actions)
            
            # Compute ratio
            ratio = torch.exp(new_log_probs - old_log_probs)
            
            # Compute surrogate losses
            surr1 = ratio * advantages
            surr2 = torch.clamp(ratio, 1 - self.epsilon, 1 + self.epsilon) * advantages
            
            # Compute actor loss
            actor_loss = -torch.min(surr1, surr2).mean()
            
            # Compute critic loss
            critic_loss = nn.MSELoss()(state_values, returns)
            
            # Total loss
            loss = actor_loss + 0.5 * critic_loss
            
            # Optimize
            self.optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.policy.parameters(), 0.5)
            self.optimizer.step()
    
    def save(self, filepath: str):
        """Save model"""
        torch.save({
            'policy_state_dict': self.policy.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
        }, filepath)
    
    def load(self, filepath: str):
        """Load model"""
        checkpoint = torch.load(filepath, map_location=self.device)
        self.policy.load_state_dict(checkpoint['policy_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
    
    def get_action_name(self, action_idx: int) -> str:
        """Get action name from index"""
        return self.ACTIONS[action_idx]
    
    def get_action_index(self, action_name: str) -> int:
        """Get action index from name"""
        return self.ACTIONS.index(action_name)

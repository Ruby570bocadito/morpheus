"""
Example: RL training loop
"""

from core.rl_agent import PPOAgent
from core.mutator import MalwareMutator
from models.classifier import MalwareClassifier
from utils.pe_parser import PEParser

def main():
    # Initialize components
    agent = PPOAgent()
    mutator = MalwareMutator(use_rl=True, use_gan=False)
    classifier = MalwareClassifier()
    classifier.load('models/pretrained/classifier.pkl')
    
    # Training loop
    episodes = 100
    
    for episode in range(episodes):
        print(f"\n=== Episode {episode + 1}/{episodes} ===")
        
        # Get initial state
        sample_file = 'samples/malware.exe'
        with PEParser(sample_file) as parser:
            state = parser.extract_all_features()
        
        # Episode
        total_reward = 0
        
        for step in range(50):
            # Select action
            action_idx, action_name, log_prob, value = agent.select_action(state)
            
            # Apply mutation (simplified)
            # In production, actually apply mutation and get new state
            
            # Calculate reward
            # reward = -detection_score (want to minimize detection)
            detection_score = classifier.get_detection_score(sample_file)
            reward = -detection_score / 100.0
            
            # Store transition
            agent.store_transition(
                state=state,
                action=action_idx,
                reward=reward,
                next_state=state,  # Simplified
                done=False,
                log_prob=log_prob,
                value=value
            )
            
            total_reward += reward
        
        # Update agent
        agent.update(batch_size=32)
        
        print(f"Total reward: {total_reward:.4f}")
        
        # Save checkpoint
        if (episode + 1) % 10 == 0:
            agent.save(f'models/checkpoints/rl_agent_ep{episode+1}.pt')
            print(f"Checkpoint saved!")
    
    # Save final model
    agent.save('models/pretrained/rl_agent.pt')
    print("\nTraining complete!")

if __name__ == '__main__':
    main()

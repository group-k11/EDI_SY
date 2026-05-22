import os
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np

# Use CPU to avoid compatibility issues across environments unless specifically requested.
# For a production deployment, this would dynamically choose "cuda", "mps", or "cpu".
DEVICE = torch.device("cpu")

class ThreatAutoencoder(nn.Module):
    """
    Autoencoder for detecting Zero-day anomalies based on reconstruction error.
    Trained on 'normal' traffic. If reconstruction error > threshold, it's an anomaly.
    """
    def __init__(self, input_dim: int):
        super(ThreatAutoencoder, self).__init__()
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 12),
            nn.ReLU(True),
            nn.Linear(12, 6),
            nn.ReLU(True),
            nn.Linear(6, 3) # Latent hidden layer
        )
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(3, 6),
            nn.ReLU(True),
            nn.Linear(6, 12),
            nn.ReLU(True),
            nn.Linear(12, input_dim)
        )
        
        self.threshold = 0.0

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
        
    def fit(self, X_normal: np.ndarray, epochs: int = 10, batch_size: int = 64, lr: float = 0.001):
        """Train the autoencoder purely on normal data."""
        if len(X_normal) == 0:
            print("[!] No normal data provided for Autoencoder training.")
            return

        self.train()
        self.to(DEVICE)
        
        dataset = TensorDataset(torch.FloatTensor(X_normal))
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        criterion = nn.MSELoss()
        optimizer = optim.Adam(self.parameters(), lr=lr)
        
        for epoch in range(epochs):
            total_loss = 0
            for batch in loader:
                x_batch = batch[0].to(DEVICE)
                optimizer.zero_grad()
                outputs = self(x_batch)
                loss = criterion(outputs, x_batch)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
                
        # Calculate reconstruction threshold based on 95th percentile of training data
        self.eval()
        with torch.no_grad():
            x_tensor = torch.FloatTensor(X_normal).to(DEVICE)
            reconstructions = self(x_tensor)
            mse_scores = torch.mean((x_tensor - reconstructions) ** 2, dim=1)
            self.threshold = float(np.percentile(mse_scores.cpu().numpy(), 95))
            
        print(f"[+] Autoencoder trained. Anomaly threshold: {self.threshold:.5f}")

    def score(self, X: np.ndarray) -> np.ndarray:
        """Get reconstruction MSE scores."""
        self.eval()
        self.to(DEVICE)
        with torch.no_grad():
            x_tensor = torch.FloatTensor(X).to(DEVICE)
            reconstructions = self(x_tensor)
            scores = torch.mean((x_tensor - reconstructions) ** 2, dim=1)
            return scores.cpu().numpy()

    def predict(self, X: np.ndarray) -> tuple:
        """Return boolean anomalies and raw scores."""
        scores = self.score(X)
        return (scores > self.threshold), scores


class TrafficLSTM(nn.Module):
    """
    LSTM for sequential attack classification.
    Expects input shape: (batch_size, sequence_length, features)
    """
    def __init__(self, input_dim: int, hidden_dim: int = 32, num_layers: int = 2, num_classes: int = 5):
        super(TrafficLSTM, self).__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        # Batch_first=True -> (batch, seq, feature)
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, dropout=0.2)
        
        # Fully connected layer for classification
        self.fc = nn.Linear(hidden_dim, num_classes)
        
    def forward(self, x):
        # x shape: (batch_size, seq_len, features)
        # We only care about the hidden state of the last sequence step
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_dim).to(DEVICE)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_dim).to(DEVICE)
        
        out, _ = self.lstm(x, (h0, c0))
        # out[:, -1, :] -> takes the last output in the sequence
        out = self.fc(out[:, -1, :])
        return out

    def fit(self, X_seq: np.ndarray, y: np.ndarray, epochs: int = 10, batch_size: int = 64, lr: float = 0.001):
        """
        Train LSTM. X_seq shape: (num_samples, seq_len, features).
        In practice for hybrid training, we might only have single samples, so we 
        simulate sequences by repeating them or we expect pre-formatted sequences.
        """
        if len(X_seq) == 0:
            return

        self.train()
        self.to(DEVICE)
        
        dataset = TensorDataset(torch.FloatTensor(X_seq), torch.LongTensor(y))
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.parameters(), lr=lr)
        
        for epoch in range(epochs):
            total_loss = 0
            for b_x, b_y in loader:
                b_x, b_y = b_x.to(DEVICE), b_y.to(DEVICE)
                optimizer.zero_grad()
                
                outputs = self(b_x)
                loss = criterion(outputs, b_y)
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
                
        print(f"[+] LSTM trained.")

    def predict_proba(self, X_seq: np.ndarray) -> np.ndarray:
        self.eval()
        self.to(DEVICE)
        with torch.no_grad():
            x_tensor = torch.FloatTensor(X_seq).to(DEVICE)
            outputs = self(x_tensor)
            # Softmax to get probabilities
            probs = torch.softmax(outputs, dim=1)
            return probs.cpu().numpy()

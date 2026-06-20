# AI Model Pipeline

This project now includes a practical packet-feature-based AI pipeline using LightGBM.

## Files

- `backend/ai_feature_extractor.py`: extracts packet/flow features from PCAPs.
- `backend/train_ml_model.py`: trains a LightGBM classifier on labeled benign and malicious PCAP data.
- `backend/predict_ml.py`: loads a trained model and scores packets in a new PCAP.

## Recommended workflow

1. Install backend dependencies:

   ```bash
   pip install -r backend/requirements.txt
   ```

2. Prepare labeled data sets:
   - `positive/` for malicious PCAPs
   - `negative/` for benign PCAPs

3. Train model:

   ```bash
   python backend/train_ml_model.py --positive data/positive --negative data/negative
   ```

4. Score new PCAPs:
   ```bash
   python backend/predict_ml.py --pcap tests/attack.pcap
   ```

## Notes

- This approach is practical for IDS deployment because it uses extracted packet features instead of a chatbot-style LLM.
- If you later want anomaly detection, add a Kitsune-style autoencoder path.

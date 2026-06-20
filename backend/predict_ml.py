import argparse
from pathlib import Path
import pandas as pd
from joblib import load
from ai_feature_extractor import build_feature_dataframe


def main():
    parser = argparse.ArgumentParser(description='Load LightGBM model and predict on a PCAP')
    parser.add_argument('--model', type=Path, default=Path('backend/data/lightgbm_model.joblib'))
    parser.add_argument('--pcap', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('backend/data/predictions.csv'))
    args = parser.parse_args()

    if not args.model.exists():
        raise FileNotFoundError(f'Model not found: {args.model}')

    model = load(args.model)
    rows = build_feature_dataframe(args.pcap)
    df = pd.DataFrame(rows)
    if df.empty:
        raise RuntimeError('No packets found in PCAP or no features extracted.')

    scores = model.predict_proba(df)[:, 1]
    df['score'] = scores
    df['prediction'] = model.predict(df)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.output, index=False)
    print(f'Predictions saved to {args.output}')


if __name__ == '__main__':
    main()

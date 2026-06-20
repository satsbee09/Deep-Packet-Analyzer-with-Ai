import argparse
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import lightgbm as lgb
from sklearn.preprocessing import LabelEncoder
from joblib import dump
from ai_feature_extractor import build_feature_dataframe


def main():
    parser = argparse.ArgumentParser(description='Train LightGBM on packet features')
    parser.add_argument('--positive', type=Path, required=True, help='Directory with labeled malicious PCAPs')
    parser.add_argument('--negative', type=Path, required=True, help='Directory with clean PCAPs')
    parser.add_argument('--output', type=Path, default=Path('backend/data/lightgbm_model.joblib'), help='Output model path')
    args = parser.parse_args()

    rows = []
    for pcap_file in sorted(args.positive.glob('*.pcap')):
        rows.extend(build_feature_dataframe(pcap_file, label='malicious'))
    for pcap_file in sorted(args.negative.glob('*.pcap')):
        rows.extend(build_feature_dataframe(pcap_file, label='benign'))

    df = pd.DataFrame(rows)
    if df.empty:
        raise RuntimeError('No features extracted from training data.')
    X = df.drop(columns=['label'])
    y = LabelEncoder().fit_transform(df['label'])
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = lgb.LGBMClassifier(n_estimators=200, learning_rate=0.1, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=['benign', 'malicious']))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    dump(model, args.output)
    print(f'Trained model saved to {args.output}')


if __name__ == '__main__':
    main()

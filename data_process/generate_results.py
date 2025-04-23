import csv
from sklearn.metrics import classification_report, accuracy_score
import argparse
from sklearn.metrics import precision_score, recall_score, f1_score

def load_true_labels(test_file):
    with open(test_file, newline='') as f:
        reader = csv.DictReader(f, delimiter='\t')
        return [int(row['label']) for row in reader]

def load_predicted_labels(pred_file):
    with open(pred_file, 'r') as f:
        return [int(line.strip()) for line in f if line.strip().isdigit()]

def main():
    parser = argparse.ArgumentParser(description='Evaluate classification results.')
    parser.add_argument('--test-file', type=str, required=True, help='Path to the test file')
    parser.add_argument('--pred-file', type=str, required=True, help='Path to the prediction file')
    args = parser.parse_args()

    y_true = load_true_labels(args.test_file)
    y_pred = load_predicted_labels(args.pred_file)

    assert len(y_true) == len(y_pred), "Mismatch in number of samples!"


    AC = accuracy_score(y_true, y_pred)
    PR = precision_score(y_true, y_pred, average='macro')
    RC = recall_score(y_true, y_pred, average='macro')
    F1 = f1_score(y_true, y_pred, average='macro')

    print(f"Accuracy (AC): {AC:.4f}")
    print(f"Precision (PR): {PR:.4f}")
    print(f"Recall (RC): {RC:.4f}")
    print(f"F1 Score: {F1:.4f}")
    
    print("Accuracy:", accuracy_score(y_true, y_pred))
    print("\nDetailed Report:\n")

if __name__ == "__main__":
    main()
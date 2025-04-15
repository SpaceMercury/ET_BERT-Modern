import csv
from sklearn.metrics import classification_report, accuracy_score

def load_true_labels(test_file):
    with open(test_file, newline='') as f:
        reader = csv.DictReader(f, delimiter='\t')
        return [int(row['label']) for row in reader]

def load_predicted_labels(pred_file):
    with open(pred_file, 'r') as f:
        return [int(line.strip()) for line in f if line.strip().isdigit()]

def main():

    pol_test_path = "./test_dataset.tsv"
    pol_pred_path = "./prediction.tsv"

    test_path = "datasets/cstnet-tls1.3/packet/test_dataset.tsv"
    pred_path = "datasets/cstnet-tls1.3/packet/prediction.tsv"

    y_true = load_true_labels(pol_test_path)
    y_pred = load_predicted_labels(pol_pred_path)

    assert len(y_true) == len(y_pred), "Mismatch in number of samples!"

    print("Accuracy:", accuracy_score(y_true, y_pred))
    print("\nDetailed Report:\n")
    print(classification_report(y_true, y_pred, digits=4))

if __name__ == "__main__":
    main()
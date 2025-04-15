python3 data_process/generate_testing.py --dataset_level packet --max_packets 5000 --pcap_path ./adobePcaps --training

PYTHONPATH=. python3 fine_tuning/run_classifier.py --pretrained_model_path models/pre-trained_model.bin \
                                   --vocab_path models/encryptd_vocab.txt \
                                   --train_path ./train_dataset.tsv \
                                   --dev_path ./valid_dataset.tsv \
                                   --test_path ./test_dataset.tsv \
                                   --epochs_num 2 --batch_size 32 --embedding word_pos_seg \
                                   --encoder transformer --mask fully_visible \
                                   --seq_length 128 --learning_rate 2e-5
                                
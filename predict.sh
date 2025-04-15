python3 data_process/generate_testing.py --dataset_level packet --max_packets 5000 --pcap_file ./adobePcaps/adobecom/6.pcap --label 1


python3 inference/run_classifier_infer.py --load_model_path models/finetuned_model.bin \
                                          --vocab_path models/encryptd_vocab.txt \
                                          --test_path ./test_nolabel_dataset.tsv \
                                          --prediction_path ./prediction.tsv \
                                          --labels_num 2 \
                                          --embedding word_pos_seg --encoder transformer --mask fully_visible
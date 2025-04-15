# ET-BERT-Modern : An updated and ready to run version of ET-BERT for linux systems 


ET-BERT-Modern is a streamlined and updated fork of the original ET-BERT repository, created in response to numerous issues encountered while running the original codebase — including outdated dependencies, broken scripts, and limited documentation. This version has been modernized to work smoothly on Linux systems, with updated libraries, cleaner and more maintainable code, and significantly improved documentation to make setup and experimentation easier for new users and researchers alike.


## Environment setup:

This was tested on an NVIDIA A30 GPU, running CUDA 12.8. The original repo runs an older CUDA version (11.4). To install, create a new environment, you may use conda for this:
```
conda create -n bertEnv
conda activate bertEnv
```

And install all of the packages from the `requirements.txt` file.
You should also make sure you have the cuda drivers installed before for your GPU.
```
pip install -r requirements.txt
```



## Running:



This repo is not meant to be pre-trained again, we use the already provided `pretrained.bin` file from the original repo. It is meant to be able to be finetuned quickly as well as tested with different pcaps.

Find the `pretrained.bin` file: [Using ET-BERT](#using-et-bert)

Organizing PCAP Files
To prepare your data for testing or fine-tuning, organize your PCAP files as follows:

1. Create a Folder for Each Application Category:
Inside the pcaps directory, create a subfolder for each application category you want to test. For example:
```
pcaps/
├── adobe/
│   ├── file1.pcap
│   ├── file2.pcap
├── youtube/
│   ├── file1.pcap
│   ├── file2.pcap
```

2. Place PCAP Files in the Corresponding Folders:
Add all PCAP files for a specific category into its respective folder.

---

Running the Scripts
1. Fine-Tuning
Run the `finetune.sh` script to:

- Generate testing data using the generate_testing.py script.
- Fine-tune the model using the finetuning/run_classifier function.

This process will create a fine-tuned model named finetuned_model.bin.

2. Inference
To perform inference, use the `predict.sh` script. This script:

Takes a PCAP file with a label.
Generates a `.tsv` file.
Feeds the `.tsv` file to the model for inference.
Outputs statistics for the predictions.

---

Example Workflow
1. Organize your PCAP files as described above.
2. Run the following command to fine-tune the model:
```
./finetune.sh
```
3. After fine-tuning, use the following command to perform inference:
```
./predict.sh
```



## Datasets
The real-world TLS 1.3 dataset is collected from March to July 2021 on China Science and Technology Network (CSTNET). For privacy considerations, we only release the anonymous data (see in [CSTNET-TLS 1.3](CSTNET-TLS%201.3/readme.md)).

Other datasets we used for comparison experiments are publicly available, see the [paper](https://arxiv.org/abs/2202.06335) for more details. If you want to use your own data, please check if the data format is the same as `datasets/cstnet-tls1.3/` and specify the data path in `data_process/`.

<br/>

## Using ET-BERT
You can now use ET-BERT directly through the pre-trained [model](https://drive.google.com/file/d/1r1yE34dU2W8zSqx1FkB8gCWri4DQWVtE/view?usp=sharing) or download via:
```
wget -O pretrained_model.bin https://drive.google.com/file/d/1r1yE34dU2W8zSqx1FkB8gCWri4DQWVtE/view?usp=sharing
```

After obtaining the pre-trained model, ET-BERT could be applied to the spetic task by fine-tuning at packet-level with labeled network traffic:
```
python3 fine-tuning/run_classifier.py --pretrained_model_path models/pre-trained_model.bin \
                                   --vocab_path models/encryptd_vocab.txt \
                                   --train_path datasets/cstnet-tls1.3/packet/train_dataset.tsv \
                                   --dev_path datasets/cstnet-tls1.3/packet/valid_dataset.tsv \
                                   --test_path datasets/cstnet-tls1.3/packet/test_dataset.tsv \
                                   --epochs_num 10 --batch_size 32 --embedding word_pos_seg \
                                   --encoder transformer --mask fully_visible \
                                   --seq_length 128 --learning_rate 2e-5
```

The default path of the fine-tuned classifier model is `models/finetuned_model.bin`. Then you can do inference with the fine-tuned model:
```
python3 inference/run_classifier_infer.py --load_model_path models/finetuned_model.bin \
                                          --vocab_path models/encryptd_vocab.txt \
                                          --test_path datasets/cstnet-tls1.3/packet/nolabel_test_dataset.tsv \
                                          --prediction_path datasets/cstnet-tls1.3/packet/prediction.tsv \
                                          --labels_num 120 \
                                          --embedding word_pos_seg --encoder transformer --mask fully_visible
```
<br/>






## Citation
#### If you are using the original work (e.g. pre-trained model) in ET-BERT for academic work, please cite the [paper](https://dl.acm.org/doi/10.1145/3485447.3512217) published in WWW 2022:

```
@inproceedings{lin2022etbert,
  author    = {Xinjie Lin and
               Gang Xiong and
               Gaopeng Gou and
               Zhen Li and
               Junzheng Shi and
               Jing Yu},
  title     = {{ET-BERT:} {A} Contextualized Datagram Representation with Pre-training
               Transformers for Encrypted Traffic Classification},
  booktitle = {{WWW} '22: The {ACM} Web Conference 2022, Virtual Event, Lyon, France,
               April 25 - 29, 2022},
  pages     = {633--642},
  publisher = {{ACM}},
  year      = {2022}
}
```

<br/>

## Contact
Please post a Github issue if you have any questions. Welcome to discuss new ideas, techniques, and improvements!

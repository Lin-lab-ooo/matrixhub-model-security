"""Materialise a state-dict checkpoint into a model directory the audit can load.

The audit takes HuggingFace model directories (so the base can be declared and
diffed). Training runs here produce bare state dicts; this converts them without
copying the tokenizer twice.
"""
import argparse
import os
import shutil

import torch


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, help="base model directory")
    parser.add_argument("--ckpt", required=True, help="state dict produced by lab.py")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    from transformers import AutoModelForCausalLM, AutoTokenizer
    model = AutoModelForCausalLM.from_pretrained(args.base, torch_dtype=torch.bfloat16)
    model.load_state_dict(torch.load(args.ckpt, map_location="cpu"))
    os.makedirs(args.out, exist_ok=True)
    model.save_pretrained(args.out, safe_serialization=True)
    tokenizer = AutoTokenizer.from_pretrained(args.base)
    tokenizer.save_pretrained(args.out)
    print("materialised", args.out)


if __name__ == "__main__":
    main()
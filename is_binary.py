#!/usr/bin/env python3
import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file', nargs=1)
    args = parser.parse_args()
    with open(args.file[0], 'rb') as f:
        if b'\x00' in f.read():
            print('The file is binary!')
        else:
            print('The file is not binary!')

#!/bin/python3

import subprocess

def get_iface_info(match=None):
    proc = subprocess.Popen("iwconfig", stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    out = proc.stdout.read().decode('utf-8')
    blocks = [b for b in out.split('\n\n') if b]
    infos = {}
    for block in blocks:
        iface, block = block.split(' ', 1)
        ieee, block = block.strip().split('  ', 1)
        if match and match != iface:
            continue
        info = {}
        info['Interface'] = iface
        info['IEEE'] = ieee
        block = block.replace('short  long', 'short long')
        block = block.replace('  ', '\n')
        lines = [l.strip() for l in block.splitlines() if l]
        lines = [l.replace('"', '') for l in lines]
        lines = [l.replace(': ', ':') for l in lines]
        lines = [l.replace(':', '=', 1) for l in lines if l]
        lines = [l.split('=', 1) for l in lines]
        for k, v in lines:
            info[k] = v
        if match:
            return info
        else:
            infos[iface] = info
    return infos

if __name__ == '__main__':
    info = get_iface_info()
    for k, v in list(info.values())[0].items():
        print(f'{k:<30}\t{v}')

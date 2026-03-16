#!/usr/bin/env python3
"""sshkeygen - SSH key management utilities."""
import subprocess, argparse, os, sys, hashlib, base64, glob

SSH_DIR = os.path.expanduser('~/.ssh')

def list_keys():
    keys = []
    for pub in glob.glob(os.path.join(SSH_DIR, '*.pub')):
        priv = pub[:-4]
        with open(pub) as f:
            parts = f.read().strip().split()
        algo = parts[0] if parts else '?'
        comment = parts[2] if len(parts) > 2 else ''
        # Fingerprint
        try:
            key_data = base64.b64decode(parts[1])
            fp = hashlib.sha256(key_data).digest()
            fp_str = 'SHA256:' + base64.b64encode(fp).decode().rstrip('=')
        except: fp_str = '?'
        keys.append({
            'file': os.path.basename(priv),
            'algo': algo, 'comment': comment,
            'fingerprint': fp_str,
            'has_private': os.path.exists(priv)
        })
    return keys

def main():
    p = argparse.ArgumentParser(description='SSH key management')
    sub = p.add_subparsers(dest='cmd')
    
    ls = sub.add_parser('list', help='List SSH keys')
    
    gen = sub.add_parser('generate', help='Generate new key pair')
    gen.add_argument('-t', '--type', default='ed25519', choices=['ed25519','rsa','ecdsa'])
    gen.add_argument('-b', '--bits', type=int, default=4096, help='Key bits (RSA only)')
    gen.add_argument('-C', '--comment', default='', help='Key comment')
    gen.add_argument('-f', '--file', help='Output filename')
    gen.add_argument('-N', '--passphrase', default='', help='Passphrase')
    
    fp = sub.add_parser('fingerprint', help='Show key fingerprint')
    fp.add_argument('file')
    
    pub = sub.add_parser('pubkey', help='Show public key')
    pub.add_argument('file', nargs='?', default='id_ed25519')
    
    au = sub.add_parser('authorized', help='Manage authorized_keys')
    au.add_argument('action', choices=['list','add','remove'])
    au.add_argument('key', nargs='?')
    
    args = p.parse_args()
    if not args.cmd: args.cmd = 'list'
    
    if args.cmd == 'list':
        keys = list_keys()
        if not keys: print("No SSH keys found."); return
        for k in keys:
            priv = '✓' if k['has_private'] else '✗'
            print(f"  {k['file']:<25} {k['algo']:<25} {k['fingerprint'][:40]}")
            if k['comment']: print(f"    Comment: {k['comment']}")
    
    elif args.cmd == 'generate':
        fname = args.file or os.path.join(SSH_DIR, f'id_{args.type}')
        if os.path.exists(fname):
            print(f"Key already exists: {fname}"); sys.exit(1)
        cmd = ['ssh-keygen', '-t', args.type, '-f', fname, '-N', args.passphrase]
        if args.comment: cmd += ['-C', args.comment]
        if args.type == 'rsa': cmd += ['-b', str(args.bits)]
        subprocess.run(cmd)
    
    elif args.cmd == 'fingerprint':
        subprocess.run(['ssh-keygen', '-lf', args.file])
    
    elif args.cmd == 'pubkey':
        pub_file = os.path.join(SSH_DIR, args.file + '.pub') if '/' not in args.file else args.file
        if not pub_file.endswith('.pub'): pub_file += '.pub'
        if os.path.exists(pub_file):
            with open(pub_file) as f: print(f.read().strip())
        else:
            print(f"Not found: {pub_file}")
    
    elif args.cmd == 'authorized':
        auth_file = os.path.join(SSH_DIR, 'authorized_keys')
        if args.action == 'list':
            if os.path.exists(auth_file):
                with open(auth_file) as f:
                    for i, line in enumerate(f, 1):
                        parts = line.strip().split()
                        comment = parts[2] if len(parts) > 2 else ''
                        print(f"  {i}. {parts[0][:20]}... {comment}")
            else:
                print("No authorized_keys file")
        elif args.action == 'add' and args.key:
            os.makedirs(SSH_DIR, exist_ok=True)
            with open(auth_file, 'a') as f: f.write(args.key.strip() + '\n')
            os.chmod(auth_file, 0o600)
            print("Key added")
        elif args.action == 'remove' and args.key:
            if os.path.exists(auth_file):
                with open(auth_file) as f: lines = f.readlines()
                lines = [l for l in lines if args.key not in l]
                with open(auth_file, 'w') as f: f.writelines(lines)
                print("Key removed")

if __name__ == '__main__':
    main()

import eth_account
import random
import string
import json
from pathlib import Path
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware  # Necessary for POA chains


def merkle_assignment():
    num_of_primes = 8192
    primes = generate_primes(num_of_primes)
    leaves = convert_leaves(primes)
    tree = build_merkle(leaves)

    random_leaf_index = random.randint(0, len(primes) - 1)
    proof = prove_merkle(tree, random_leaf_index)

    challenge = ''.join(random.choice(string.ascii_letters) for _ in range(32))
    addr, sig = sign_challenge(challenge)

    if sign_challenge_verify(challenge, addr, sig):
        tx_hash = send_signed_msg(proof, leaves[random_leaf_index])
        print(f"Transaction hash: {tx_hash}")


def generate_primes(num_primes):
    primes_list = []
    limit = 100000
    sieve = [True] * limit
    sieve[0:2] = [False, False]
    for i in range(2, limit):
        if sieve[i]:
            primes_list.append(i)
            if len(primes_list) == num_primes:
                break
            for j in range(i * i, limit, i):
                sieve[j] = False
    return primes_list


def convert_leaves(primes_list):
    return [int(p).to_bytes(32, byteorder='big') for p in primes_list]


def build_merkle(leaves):
    tree = [leaves]
    current_layer = leaves

    while len(current_layer) > 1:
        next_layer = []
        for i in range(0, len(current_layer), 2):
            a = current_layer[i]
            b = current_layer[i + 1] if i + 1 < len(current_layer) else a
            hashed = hash_pair(a, b)
            next_layer.append(hashed)
        tree.append(next_layer)
        current_layer = next_layer

    return tree


def prove_merkle(merkle_tree, random_indx):
    proof = []
    index = random_indx

    for level in merkle_tree[:-1]:
        sibling_index = index ^ 1
        if sibling_index < len(level):
            proof.append(level[sibling_index])
        index //= 2

    return proof


def sign_challenge(challenge):
    acct = get_account()
    message = eth_account.messages.encode_defunct(text=challenge)
    sig_obj = eth_account.Account.sign_message(message, acct.key)
    return acct.address, sig_obj.signature.hex()


def send_signed_msg(proof, random_leaf):
    chain = 'bsc'
    acct = get_account()
    address, abi = get_contract_info(chain)
    w3 = connect_to(chain)

    contract = w3.eth.contract(address=address, abi=abi)

    tx = contract.functions.submit(proof, random_leaf).build_transaction({
        'from': acct.address,
        'nonce': w3.eth.get_transaction_count(acct.address),
        'gas': 500000,
        'gasPrice': w3.to_wei('10', 'gwei'),
    })

    signed_tx = w3.eth.account.sign_transaction(tx, private_key=acct.key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

    return w3.to_hex(tx_hash)


# --- Helpers (unchanged) ---

def connect_to(chain):
    if chain not in ['avax', 'bsc']:
        print(f"{chain} is not a valid option for 'connect_to()'")
        return None
    if chain == 'avax':
        api_url = f"https://api.avax-test.network/ext/bc/C/rpc"
    else:
        api_url = f"https://data-seed-prebsc-1-s1.binance.org:8545/"
    w3 = Web3(Web3.HTTPProvider(api_url))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3


def get_account():
    cur_dir = Path(__file__).parent.absolute()
    with open(cur_dir.joinpath('sk.txt'), 'r') as f:
        sk = f.readline().rstrip()
    if sk[0:2] == "0x":
        sk = sk[2:]
    return eth_account.Account.from_key(sk)


def get_contract_info(chain):
    contract_file = Path(__file__).parent.absolute() / "contract_info.json"
    if not contract_file.is_file():
        contract_file = Path(__file__).parent.parent.parent / "tests" / "contract_info.json"
    with open(contract_file, "r") as f:
        d = json.load(f)
        d = d[chain]
    return d['address'], d['abi']


def sign_challenge_verify(challenge, addr, sig):
    eth_encoded_msg = eth_account.messages.encode_defunct(text=challenge)
    if eth_account.Account.recover_message(eth_encoded_msg, signature=sig) == addr:
        print(f"Success: signed the challenge {challenge} using address {addr}!")
        return True
    else:
        print(f"Failure: The signature does not verify!")
        print(f"signature = {sig}\naddress = {addr}\nchallenge = {challenge}")
        return False


def hash_pair(a, b):
    if a < b:
        return Web3.solidity_keccak(['bytes32', 'bytes32'], [a, b])
    else:
        return Web3.solidity_keccak(['bytes32', 'bytes32'], [b, a])


if __name__ == "__main__":
    merkle_assignment()

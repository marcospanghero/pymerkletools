import hashlib
import binascii
import os
import hmac
from tqdm import tqdm
from collections import deque
import math
import itertools


from struct import *

try:
    import sha3
except ModuleNotFoundError:
    from warnings import warn
    warn("sha3 is not working!")


class secMerkleTools(object):
    def __init__(self, hash_type="sha256", isSecure=False, key=None):
        hash_type = hash_type.lower()
        self.secureTree = isSecure
        if self.secureTree:
            if key is None:
                print('Key not specified, generating a random 128 bit KEY:')
                self.key = os.urandom(16)
                print('Key is : {}'.format(binascii.hexlify(self.key)))
            else:
                self.key = key
                print('Using supplied key {}'.format(binascii.hexlify(self.key)))
            if hash_type in ['sha256', 'md5', 'sha224', 'sha384', 'sha512',
                             'sha3_256', 'sha3_224', 'sha3_384', 'sha3_512']:
                self.digestmod = hash_type
                self.hash_function = getattr(hashlib, hash_type)
            else:
                raise Exception('`hash_type` {} nor supported'.format(hash_type))
        else:
            if hash_type in ['sha256', 'md5', 'sha224', 'sha384', 'sha512',
                             'sha3_256', 'sha3_224', 'sha3_384', 'sha3_512']:
                self.hash_function = getattr(hashlib, hash_type)
                self.key = None
            else:
                raise Exception('`hash_type` {} nor supported'.format(hash_type))
        self.reset_tree()

    def _to_hex(self, x):
        try:  # python3
            return x.hex()
        except:  # python2
            return binascii.hexlify(x)

    def reset_tree(self):
        self.leaves = deque()
        self.secure_leaves = deque()
        self.levels = None
        self.cb = []
        self.is_ready = False

    def add_leaf(self, values, do_hash=False, do_seq=True):
        print('Adding Leafs')
        self.is_ready = False
        seq = 0
        # check if single leaf
        if not isinstance(values, tuple) and not isinstance(values, list):
            values = [values]
        for v in tqdm(values):
            if do_seq is True:
                payload = pack('>I',v) + pack('>I', seq)
            else:
                payload = pack('>I',v)
            if do_hash:
                hash_v = self.hash_function(payload).digest()
                # print('[{}]\t[{}] Leaf {}: \t{}'.format(seq, v, payload, self._to_hex(hash_v)))
                self.leaves.append(hash_v)
            else:
                # print('[{}]\t[{}] Leaf {}'.format(seq, v, payload))
                self.leaves.append(payload)
            seq += 1

    def get_leaf(self, index, isRaw=False):
        if isRaw == True:
            return self.leaves[index]
        else:
            return self._to_hex(self.leaves[index])

    def get_leaf_count(self):
        return len(self.leaves)

    def get_levels_count(self):
        return len(self.levels)

    def get_tree_ready_state(self):
        return self.is_ready

    def get_cb_vector(self):
        return self.cb

    def _calculate_next_level(self):
        solo_leave = None
        buffer = deque()
        N = len(self.levels[0])  # number of leaves on the level
        if N % 2 == 1:  # if odd number of leaves on the level
            solo_leave = self.levels[0][-1]
            N -= 1

        new_level = deque()
        for l, r in zip(self.levels[0][0:N:2], self.levels[0][1:N:2]):
            new_level.append(self.hash_function(l + r).digest())
        if solo_leave is not None:
            new_level.append(solo_leave)
        buffer.appendleft(new_level)
        self.levels = buffer

    def _calculate_next_level_sec(self):
        solo_leave = None
        buffer = deque()

        N = len(self.levels[0])  # number of leaves on the level
        if N % 2 == 1:  # if odd number of leaves on the level
            solo_leave = self.levels[0][-1]
            N -= 1

        new_level = deque()
        c_lvl = 0
        for l, r in zip(self.levels[0][0:N:2], self.levels[0][1:N:2]):
            new_level.append(hmac.new(self.key, str(l + r).encode('utf-8'), digestmod=self.digestmod).digest())
        if solo_leave is not None:
            new_level.append(solo_leave)

        buffer.appendleft(new_level)
        self.levels = buffer


    def _calculate_next_list(self, seed, rotate_frequency=1):
        N = int(self.get_leaf_count() / rotate_frequency)
        buffer = deque()
        initial_element = self.hash_function(seed).digest()
        buffer.append(initial_element)
        for k in tqdm(range(1, N)):
            list_element = self.hash_function(buffer[k-1]).digest()
            buffer.append(list_element)
        self.levels = buffer

    def _calculate_secure_leaves(self):

            K = int(self.get_levels_count())
            N = int(self.get_leaf_count())
            rotate_freq = int(N/K)
            for n in range(0, N):
                secure_leaf = hmac.new(self.levels[K - int(n/rotate_freq) - 1], self.leaves[n],
                                      digestmod=self.digestmod).digest()
                print('Leaf {}\t: [{}] with key: {} -> {}'.format(n, binascii.hexlify(self.leaves[n]), binascii.hexlify(self.levels[K - int(n/rotate_freq) - 1]), binascii.hexlify(secure_leaf)))
                self.secure_leaves.append(secure_leaf)


    def generate_cb_vector(self, is_equally_spaced=True, granularity_cb = 100):
        N = self.get_leaf_count()
        slices_list = []
        '''Check if N is a power of 2, if not raise exception'''
        if is_equally_spaced:
            for k in range(0, N, granularity_cb):
                self.cb.append(hex(self.levels[k][-1]))
            return
        else:
            if math.log(N, 2).is_integer():
                intervals = int(math.log(N, 2))
                for i in range(1, intervals + 1):
                    slice = list(itertools.islice(self.levels,
                                                             int(pow(2, i-1) - 1),
                                                             int(math.pow(2, i)) - 1))
                    # print('[{} {}]'.format(i, len(slice)), slice)
                    byte_vector = []
                    for element in slice:
                        byte_vector.append(hex(element[-1]))
                    slices_list.append(byte_vector)
                    print('[{} {}]'.format(i, len(byte_vector)), byte_vector)
            else:
                raise Exception('Warning', 'The list has not integer log2 elements. Cannot use this method')
                return
        return slices_list


    def _print_tree(self, levels):
        r_c = 0
        r_l = 0
        for line in levels:
            for col in line:
                print('[{}][{}] - {}'.format(r_l, r_c, self._to_hex(col)))
                r_c += 1
            r_l += 1
            r_c = 0
            print()

    def _print_list(self, levels):
        r_l = 0
        for element in levels:
            print('[{}] - \t{}'.format(r_l, self._to_hex(element)))
            r_l += 1
        r_l = 0

    def make_tree(self):
        self.is_ready = False
        if self.get_leaf_count() > 0:
            self.levels = [self.leaves, ]
            while len(self.levels[0]) > 1:
                self._calculate_next_level()
            # self._print_tree(self.levels)
        self.is_ready = True

    def make_list(self, seed=None, rotate_frequency=1):
        print('Making List')
        self.is_ready = False
        self.levels = list()
        self._calculate_next_list(seed=seed, rotate_frequency=rotate_frequency)
        if self.secureTree:
            self._calculate_secure_leaves()
        print("levels of list")
        self._print_list(self.levels)
        print('leaves of list')
        self._print_list(self.leaves)
        print('secure leaves of list')
        self._print_list(self.secure_leaves)
        self.is_ready = True

    def get_merkle_root(self):
        if self.is_ready:
            if self.levels is not None:
                return self._to_hex(self.levels[0])
            else:
                return None
        else:
            return None

    def get_proof(self, index):
        if self.levels is None:
            return None
        elif not self.is_ready or index > len(self.leaves) - 1 or index < 0:
            return None
        else:
            proof = []
            for x in range(len(self.levels) - 1, 0, -1):
                level_len = len(self.levels[x])
                if (index == level_len - 1) and (level_len % 2 == 1):  # skip if this is an odd end node
                    index = int(index / 2.)
                    continue
                is_right_node = index % 2
                sibling_index = index - 1 if is_right_node else index + 1
                sibling_pos = "left" if is_right_node else "right"
                sibling_value = self._to_hex(self.levels[x][sibling_index])
                proof.append({sibling_pos: sibling_value})
                index = int(index / 2.)
            return proof

    def get_chain_element(self, index):
        if self.levels is None:
            return None
        elif not self.is_ready or index > len(self.levels) - 1 or index < 0:
            return None
        else:
            return self._to_hex(self.levels[index])

    def validate_proof(self, proof, target_hash, merkle_root):
        merkle_root = bytearray.fromhex(merkle_root)
        target_hash = bytearray.fromhex(target_hash)
        if len(proof) == 0:
            return target_hash == merkle_root
        else:
            proof_hash = target_hash
            for p in proof:
                # if self.secureTree:
                #     try:
                #         # the sibling is a left node
                #         sibling = bytearray.fromhex(p['left'])
                #         proof_hash = hmac.new(self.key, str(sibling + proof_hash).encode('utf-8'),
                #                               digestmod=self.digestmod).digest()
                #     except:
                #         # the sibling is a right node
                #         sibling = bytearray.fromhex(p['right'])
                #         proof_hash = hmac.new(self.key, str(proof_hash + sibling).encode('utf-8'),
                #                               digestmod=self.digestmod).digest()
                # else:
                try:
                    # the sibling is a left node
                    sibling = bytearray.fromhex(p['left'])
                    proof_hash = self.hash_function(sibling + proof_hash).digest()
                except:
                    # the sibling is a right node
                    sibling = bytearray.fromhex(p['right'])
                    proof_hash = self.hash_function(proof_hash + sibling).digest()
                print('Proof {} - proofhash: {}'.format(p, self._to_hex(proof_hash)))
            return proof_hash == merkle_root

    def get_key(self):
        return self.key

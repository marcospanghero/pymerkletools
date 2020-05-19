import hashlib
import binascii
import  os
import hmac
from tqdm import tqdm
from collections import deque

try:
    import sha3
except:
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
                print('Key is : {}'.format(self._to_hex(self.key)))
            else:
                self.key = key
                print('Using supplied key {}'.format(self.key))
            if hash_type in ['sha256', 'md5', 'sha224', 'sha384', 'sha512',
                             'sha3_256', 'sha3_224', 'sha3_384', 'sha3_512']:
                self.digestmod=hash_type
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
        self.levels = None
        self.is_ready = False

    def add_leaf(self, values, do_hash=False, do_seq=True):
        print('Adding Leafs')
        self.is_ready = False
        seq = 0
        # check if single leaf
        if not isinstance(values, tuple) and not isinstance(values, list):
            values = [values]
        for v in tqdm(values):
            if do_hash:
                if self.secureTree:
                    hash_v = hmac.new(self.key, str(v + seq).encode('utf-8'), digestmod=self.digestmod).digest()
                    #print('Printing HASHED v {} : {}'.format(v, hash_v))
                else:
                    hash_v = self.hash_function(str(v + seq).encode('utf-8')).digest()
            #print('Leaf {}: {}'.format(value, self._to_hex(hash_v)))
            self.leaves.append(hash_v)
            seq += 1

    def get_leaf(self, index, isRaw=False):
        if isRaw==True:
            return self.leaves[index]
        else:
            return self._to_hex(self.leaves[index])

    def get_leaf_count(self):
        return len(self.leaves)

    def get_tree_ready_state(self):
        return self.is_ready

    def _calculate_next_level(self):
        solo_leave = None
        buffer = deque()
        N = len(self.levels[0])  # number of leaves on the level
        if N % 2 == 1:  # if odd number of leaves on the level
            solo_leave = self.levels[0][-1]
            N -= 1

        new_level = deque()
        for l, r in zip(self.levels[0][0:N:2], self.levels[0][1:N:2]):
            new_level.append(self.hash_function(l+r).digest())
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

    def _calculate_next_list(self, anchor):
        N = self.get_leaf_count()
        buffer = deque()
        if self.secureTree:
            initial_element = hmac.new(self.key, str(self.get_leaf(0, isRaw=True) + anchor).encode('utf-8'),
                                       digestmod=self.digestmod).digest()
        else:
            initial_element = self.hash_function(self.get_leaf(0, isRaw=True) + anchor).digest()
        buffer.appendleft(initial_element)
        for k in tqdm(range(1, N)):
            if self.secureTree:
                list_element = hmac.new(self.key, str(buffer[k-1] + self.get_leaf(k, isRaw=True)).encode('utf-8'),
                                        digestmod=self.digestmod).digest()
            else:
                list_element = self.hash_function(buffer[k-1] + self.get_leaf(k, isRaw=True)).digest()
            buffer.appendleft(list_element)
        self.levels = buffer

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
            print('[{}] - {}'.format(r_l, self._to_hex(element)))
            r_l += 1

    def make_tree(self):
        self.is_ready = False
        if self.get_leaf_count() > 0:
            self.levels = [self.leaves, ]
            while len(self.levels[0]) > 1:
                self._calculate_next_level()
            #self._print_tree(self.levels)
        self.is_ready = True

    def make_list(self, anchor=None):
        print('Making List')
        self.is_ready = False
        self.levels = list()
        self._calculate_next_list(anchor=anchor)
        #self._print_list(self.levels)
        self.is_ready = True

    def get_merkle_root(self):
        if self.is_ready:
            if self.levels is not None:
                return self._to_hex(self.levels[0][0])
            else:
                return None
        else:
            return None

    def get_proof(self, index):
        if self.levels is None:
            return None
        elif not self.is_ready or index > len(self.leaves)-1 or index < 0:
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


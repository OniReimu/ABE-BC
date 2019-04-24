import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.Hash import ChamHash,Hash
from charm.toolbox.conversion import Conversion

from charm.schemes.abenc.abenc_maabe_yj14 import MAABE

class ChamHash_classic(ChamHash):

    def __init__(self):
        ChamHash.__init__(self)
        global group
        group = PairingGroup('SS512')
        self.group = group

    def paramgen(self):
        g = self.group.random(G1)
        x = self.group.random(ZR)
        h = g ** x

        pk = {'g':g, 'h':h}
        sk = {'x':x}
        return (pk, sk)

    def chamhash(self, pk, msg, r = 0):
        """ H() = g^m * h^r, h = g^x """
        g, h, msg_hash = pk['g'], pk['h'], self.group.hash(msg)
        if r == 0:
            r = group.random()
        cham_hash = (g ** msg_hash) * (h ** r)
        return (cham_hash, r)

    def forge(self, sk, msg, r, msg_forged):
        x = sk['x']
        msg_hash = self.group.hash(msg)
        msg_forged_hash = self.group.hash(msg_forged)
        r_new = (msg_hash + x * r - msg_forged_hash) / x
        return r_new

class ABE(MAABE):
    def __init__(self):
        self.users = {} # public user data
        self.authorities = {}
        self.authorityAttributes = ["ONE", "TWO", "THREE", "FOUR"]
        self.authorityID = "saber"
        self.ta_auth_info = {}

    def initialize_abe(self):
        self.maabe = MAABE(self.group)
        GPP, GMK = self.maabe.setup()
        self.new_transaction(
            sender = self.address,
            recipient = self.address,
            amount = 0,
            data = {
                'GPP': {
                    'g': Conversion.bytes2str(self.group.serialize(GPP['g'])),
                    'g_a': Conversion.bytes2str(self.group.serialize(GPP['g_a'])),
                    'g_b': Conversion.bytes2str(self.group.serialize(GPP['g_b']))
                },
                'ch_pk': {
                    'g': Conversion.bytes2str(self.group.serialize(self.pk['g'])),
                    'h': Conversion.bytes2str(self.group.serialize(self.pk['h']))
                }
            }
        )
        return GPP, GMK

    def setupAuthority(self):
        self.maabe.setupAuthority(self.ta_auth_info['GPP'], self.authorityID, self.authorityAttributes, self.authorities)
        _, pk, attrs = self.authorities[self.authorityID]
        attrs_json = {}
        for attr in self.authorityAttributes:
            attrs_json[attr] = {
                'VK': Conversion.bytes2str(self.group.serialize(attrs[attr]['VK'])),
                'PK1': Conversion.bytes2str(self.group.serialize(attrs[attr]['PK1'])),
                'PK2': Conversion.bytes2str(self.group.serialize(attrs[attr]['PK2']))
            }

        self.new_transaction(
            sender = self.address,
            recipient = self.address,
            amount = 0,
            data = {
                'auth_info': {
                    'pk': {
                        'e_alpha': Conversion.bytes2str(self.group.serialize(pk['e_alpha'])),
                        'g_beta': Conversion.bytes2str(self.group.serialize(pk['g_beta'])),
                        'g_beta_inv': Conversion.bytes2str(self.group.serialize(pk['g_beta_inv']))
                    },
                    'attrs': attrs_json
                }
            }
        )

    def register_users(self, user_id, user_url):
        self.users[user_id] = {}
        user_key, self.users[user_id]['user_public_info'] = self.maabe.registerUser(self.ta_auth_info['GPP'])
        # print(self.users[user_id])
        # send user_key to the certain user
        payload = {
            'user_key': [
                Conversion.bytes2str(self.group.serialize(user_key[0])),
                Conversion.bytes2str(self.group.serialize(user_key[1]))
            ]
        }
        headers = {'content-type': 'application/json'}

        try:
            r = requests.post(user_url, data=json.dumps(payload), headers=headers)
        except ConnectionRefusedError:
            print("Connection refused")
        except requests.exceptions.ConnectionError:
            print("Connection refused")
        else:
            if r.status_code != 200:
                print("Fail to send user_key to the corresponding user")
            else:
                print(r.text)

    def keygen_users(self, attr, user_id, user_url):
        if not attr in self.authorityAttributes:
            raise ValueError('Invalid attribute')
        if not user_id in self.users:
            raise ValueError('Unregistered users')
        else:
            if 'authoritySecretKeys' not in self.users[user_id]:
                self.users[user_id]['authoritySecretKeys'] = {}
            self.maabe.keygen(self.ta_auth_info['GPP'], self.authorities[self.authorityID], attr, self.users[user_id]['user_public_info'], self.users[user_id]['authoritySecretKeys'])
            # print(self.users[user_id]['authoritySecretKeys'])
            # send user_authKey to the certain user
            AK_json = {}
            for attr, value in self.users[user_id]['authoritySecretKeys']['AK'].items():
                AK_json[attr] = Conversion.bytes2str(self.group.serialize(value))
            payload = {
                'authoritySecretKeys': {
                    'K': Conversion.bytes2str(self.group.serialize(self.users[user_id]['authoritySecretKeys']['K'])),
                    'KS': Conversion.bytes2str(self.group.serialize(self.users[user_id]['authoritySecretKeys']['KS'])),
                    'AK': AK_json
                }
            }
            headers = {'content-type': 'application/json'}

            try:
                r = requests.post(user_url, data=json.dumps(payload), headers=headers)
            except ConnectionRefusedError:
                print("Connection refused")
            except requests.exceptions.ConnectionError:
                print("Connection refused")
            else:
                if r.status_code != 200:
                    print("Fail to send user_authKey to the corresponding user")
                else:
                    print(r.text)


class Blockchain(ChamHash_classic, ABE):
    def __init__(self):
        ChamHash_classic.__init__(self)
        ABE.__init__(self)
        self.maabe = MAABE(self.group)

        self.current_transactions = []
        self.engraved_transactions = [] ## used to record the update, cannot be edited
        self.chain = []
        self.nodes = set()

        ''' Users don't need this, self.pk is rather obtained from TA '''
        # # Initilize the chameleon hash keys
        # (self.ch_pk, self.ch_sk) = self.paramgen()

        # Initilize the abe setup  
        self.user_key = {} # user_pk, user_sk, user_authKey
        self.ch_sk = {} # ch_sk
        self.UK = {} # UKs or UKc

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block,'block')
            if block['header']['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['header']['proof'], block['header']['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """
        if len(self.chain) > 0: # excluding the genesis block
            self.engraved_transactions += self.chain[-1]['body']['engraved']
        block = {
            
            'header': {
                # c(h), n(h), h_p(h), engrave(h)
                'index': len(self.chain),
                'timestamp': time(),
                'proof': proof,
                'previous_hash': previous_hash or self.hash(self.chain[-1],'block'),
                'engraved_hash': self.hash(self.engraved_transactions,'engrave'), 
                'transaction_hash': self.hash(self.current_transactions,'tx')
            },
            'body': {
                # m(h), v(h)
                'transactions': self.current_transactions,
                # engrave(h), uneditable
                'engraved': self.engraved_transactions
            }

        }

        # Reset the current list of transactions
        self.current_transactions = []
        self.engraved_transactions = [] ## stored permanently in every new block as a smart contract scheme

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount, cham_hash='0', data={}):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :param data: Payload in the form of a dict
        :return: The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'cham_hash': cham_hash,
            'data': data
        })

        return self.last_block['header']['index'] + 1

    def new_engraved_transaction(self, sender, recipient, data={}):
        """
        Creates a new engraved transaction to the latest mined Block for recording the update

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient, should be exactly the same as that of the Sender
        :param amount: Amount should be 0
        :param data: sha256_Hash of the updated value of a certain random number
        """

        self.engraved_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'data': data
        })
        print('check block 0 inside2: {}'.format(self.chain[0]))
        return self.last_block['header']['index'] + 1

    def get_key_info(self):
        self.GPP = {}
        self.ch_pk = {}
        self.auth_info = {} # auth_pk, auth_attr
        

        self.resolve_conflicts()
        if len(self.chain) > 0:
            genesis = self.chain[0]
            for tx in genesis['body']['transactions']:
                if 'GPP' in tx['data']:
                    self.GPP['g'] = self.group.deserialize(Conversion.str2bytes(tx['data']['GPP']['g']))
                    self.GPP['g_a'] = self.group.deserialize(Conversion.str2bytes(tx['data']['GPP']['g_a']))
                    self.GPP['g_b'] = self.group.deserialize(Conversion.str2bytes(tx['data']['GPP']['g_b']))
                if 'ch_pk' in tx['data']:
                    self.ch_pk['g'] = self.group.deserialize(Conversion.str2bytes(tx['data']['ch_pk']['g']))
                    self.ch_pk['h'] = self.group.deserialize(Conversion.str2bytes(tx['data']['ch_pk']['h']))
                if 'auth_info' in tx['data']:
                    self.auth_info['pk'] = {
                        'e_alpha': self.group.deserialize(Conversion.str2bytes(tx['data']['auth_info']['pk']['e_alpha'])),
                        'g_beta': self.group.deserialize(Conversion.str2bytes(tx['data']['auth_info']['pk']['g_beta'])),
                        'g_beta_inv': self.group.deserialize(Conversion.str2bytes(tx['data']['auth_info']['pk']['g_beta_inv']))
                    }
                    auth_info_attrs_json = {}
                    for attr, value in tx['data']['auth_info']['attrs'].items():
                        auth_info_attrs_json[attr] = {
                            'VK': self.group.deserialize(Conversion.str2bytes(value['VK'])),
                            'PK1': self.group.deserialize(Conversion.str2bytes(value['PK1'])),
                            'PK2': self.group.deserialize(Conversion.str2bytes(value['PK2']))
                        }
                    self.auth_info['attrs'] = auth_info_attrs_json

        else:
            raise ValueError('No block has been generated yet')

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block_or_tx, flag):
        """
        Creates a SHA-256 hash of a Block or a Transaction

        :param block: Block or Transaction
        """
        def eliminate_data_field(tx):
            tx_deep_copy = tx.copy()
            tx_deep_copy.pop('data')
            return tx_deep_copy
        if flag == 'block':       
            block_without_tx = block_or_tx.copy()
            body = block_without_tx['body'].copy()
            if 'transactions' in block_without_tx['body']:
                body.pop('transactions')
            block_string = json.dumps(body, sort_keys=True).encode()
            return hashlib.sha256(block_string).hexdigest()
        elif flag == 'tx':
            tx_without_data = list(map(eliminate_data_field, block_or_tx[:]))
            tx_string = json.dumps(tx_without_data, sort_keys=True).encode()
            return hashlib.sha256(tx_string).hexdigest()
        elif flag == 'engrave':
            engrave_string = json.dumps(block_or_tx, sort_keys=True).encode()
            return hashlib.sha256(engrave_string).hexdigest()    
        elif flag == 'random':
            return hashlib.sha256(block_or_tx.encode()).hexdigest()       
        else:
            return "" 
        # # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        # block_tx_string = json.dumps(block_or_tx, sort_keys=True).encode()
        # return hashlib.sha256(block_tx_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['header']['proof']
        last_hash = self.hash(last_block,'block')

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # # We must receive a reward for finding the proof.
    # # The sender is "0" to signify that this node has mined a new coin.
    # blockchain.new_transaction(
    #     sender="0",
    #     recipient=node_identifier,
    #     amount=1,
    # )

    # Finalize the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block,'block')
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Added",
        'index': block['header']['index'],
        'transactions': block['body']['transactions'],
        'engraved': block['body']['engraved'],
        'transaction_hash': block['header']['transaction_hash'],
        'proof': block['header']['proof'],
        'previous_hash': block['header']['previous_hash'],
        'engraved_hash': block['header']['engraved_hash'],
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount', 'data']
    if not all(k in values for k in required):
        return 'Missing values', 400

    try:
        data_str = values['data']
        data_str = data_str.replace("'","\"")
        # print(data_str)
        data_dict = json.loads(data_str) # converted to JSON
    except ValueError:
        return 'Invalid data format', 400
    else:
        # Cham Hash the transaction data
        (cham_hash, random) = blockchain.chamhash(blockchain.ch_pk, json.dumps(data_dict, sort_keys=True).encode(), r = 0)
        tran_hash = Conversion.bytes2str(blockchain.group.serialize(cham_hash))
        random = Conversion.bytes2str(blockchain.group.serialize(random))
        if "random" in data_dict:
            return 'The random field is reserved', 400
        else:
            data_dict["random"] = random
        # Create a new Transaction
        index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'], tran_hash, data_dict)

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        print(node)
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

@app.route('/get_block', methods=['POST'])
def get_block_by_index():
    values = request.get_json()

    index = values.get('block_index')
    if index is None:
        return "Error: Please supply an invalid index", 400

    if int(index) >= len(blockchain.chain) or int(index) < 0:
        return "Error: Index out of range", 400
    response = {
        'index': index,
        'block': blockchain.chain[int(index)]
    }

    return jsonify(response), 200

@app.route('/user_key_authKey', methods=['POST'])
def process_user_key_authKey():
    values = request.get_json()

    if 'user_key' in values:
        user_key_raw = values.get('user_key')
        user_key = (blockchain.group.deserialize(Conversion.str2bytes(user_key_raw[0])), blockchain.group.deserialize(Conversion.str2bytes(user_key_raw[1])))
        blockchain.user_key['keys'] = user_key
        # print(user_key)
    if 'authoritySecretKeys' in values:
        authoritySecretKeys_raw = values.get('authoritySecretKeys')
        AK_json = {}
        for attr, value in authoritySecretKeys_raw['AK'].items():
            AK_json[attr] = blockchain.group.deserialize(Conversion.str2bytes(value))
        authoritySecretKeys = {
            'K': blockchain.group.deserialize(Conversion.str2bytes(authoritySecretKeys_raw['K'])),
            'KS': blockchain.group.deserialize(Conversion.str2bytes(authoritySecretKeys_raw['KS'])),
            'AK': AK_json
        }
        # print(authoritySecretKeys)
        blockchain.user_key['authoritySecretKeys'] = authoritySecretKeys
    if 'ch_sk' in values:
        ch_sk_raw = values.get('ch_sk')
        blockchain.ch_sk['x'] = blockchain.group.deserialize(Conversion.str2bytes(ch_sk_raw))
        print("ch_sk:{}".format(blockchain.ch_sk['x']))

    if 'UKs' in values and 'revoked_attr' in values:
        UKs_raw = values.get('UKs')
        revoked_attr = values.get('revoked_attr')

        blockchain.UK['UKs'] = blockchain.group.deserialize(Conversion.str2bytes(UKs_raw))
        blockchain.maabe.skupdate(blockchain.user_key['authoritySecretKeys'], revoked_attr, blockchain.UK['UKs'])

    if 'UKc' in values:
        UKc_raw = values.get('UKc')
        revoked_attr = values.get('revoked_attr')

        blockchain.UK['UKc'] = (blockchain.group.deserialize(Conversion.str2bytes(UKc_raw[0])), blockchain.group.deserialize(Conversion.str2bytes(UKc_raw[1])))
        # blockchain.maabe.ckupdate(blockchain.GPP, , revoked_attr, blockchain.UK['UKc'])


    return 'Received', 200

@app.route('/get_key_info', methods=['GET'])
def get_key_info():
    blockchain.get_key_info()
    # print("GPP: {}".format(blockchain.GPP))
    # print("ch_pk: {}".format(blockchain.ch_pk))
    # print("attr_info: {}".format(blockchain.auth_info))

    response = {
        'message': 'The required info has been successfully fetched.',
    }
    return jsonify(response), 201

@app.route('/abe_encrypt', methods=['POST'])
def abe_encrypt():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['attr_policy', 'msg']
    if not all(k in values for k in required):
        return 'Missing values', 400

    if len(blockchain.GPP) or len(blockchain.ch_pk) or len(blockchain.auth_info):
        auth_info_tuple = ({}, blockchain.auth_info['pk'], blockchain.auth_info['attrs'])
        # # CT is being imported as the data field of new_transaction
        # input_msg = blockchain.group.deserialize(Conversion.str2bytes(values['msg']))
        input_msg = blockchain.group.random(GT)
        print("check input b4:{}".format(input_msg))
        CT = blockchain.maabe.encrypt(blockchain.GPP, values['attr_policy'], input_msg, auth_info_tuple)
        # print("CT in encrypt:{}".format(CT))
        # print("blockchain.GPP in encrypt:{}".format(blockchain.GPP))
        C_json = {}
        CS_json = {}
        D_json = {}
        DS_json = {}
        for key in CT['C'].keys():
            C_json[key] = Conversion.bytes2str(blockchain.group.serialize(CT['C'][key]))
            CS_json[key] = Conversion.bytes2str(blockchain.group.serialize(CT['CS'][key]))
            D_json[key] = Conversion.bytes2str(blockchain.group.serialize(CT['D'][key]))
            DS_json[key] = Conversion.bytes2str(blockchain.group.serialize(CT['DS'][key]))

        response = {
            'C1': Conversion.bytes2str(blockchain.group.serialize(CT['C1'])),
            'C2': Conversion.bytes2str(blockchain.group.serialize(CT['C2'])), 
            'C3': Conversion.bytes2str(blockchain.group.serialize(CT['C3'])), 
            'C': C_json, 
            'CS': CS_json, 
            'D': D_json, 
            'DS': DS_json, 
            'policy': values['attr_policy'] 
        }
        copy = json.dumps(response)
        response['copy and paste to the data field'] = copy
        # print('response:{}'.format(response))
        return jsonify(response), 200
    else:
        return 'Please fetch the key_info from genesis block created by TA first', 400

@app.route('/abe_decrypt', methods=['POST'])
def abe_decrypt():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['block_index', 'kv_ct']
    if not all(k in values for k in required):
        return 'Missing values', 400

    index = values['block_index']
    kv_ct = values['kv_ct']
    if int(index) >= len(blockchain.chain) or int(index) < 0:
        return "Error: Index out of range", 400

    for tx in blockchain.chain[int(index)]['body']['transactions']:
        if not kv_ct in tx['data']:
            return "Error: The concerned key field does not exist", 400
        else:
            CT = {}
            CT_raw = tx['data'][kv_ct]
            for key, value in CT_raw.items():
                if key == 'policy':
                    CT[key] = value
                else:
                    if type(value).__name__ == 'dict':
                        CT[key] = {}
                        for key2, value2 in value.items():
                            CT[key][key2] = blockchain.group.deserialize(Conversion.str2bytes(value2))
                    else:
                        CT[key] = blockchain.group.deserialize(Conversion.str2bytes(value))

            msg = blockchain.maabe.decrypt(blockchain.GPP, CT, blockchain.user_key)
            print("check input after:{}".format(msg))
            if not msg:
                return "This node is not permitted to decrypt this msg", 400
            # print("CT in decrypt:{}".format(CT))

            return (Conversion.bytes2str(blockchain.group.serialize(msg))), 200

@app.route('/forge', methods=['POST'])
def forge_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['block_index', 'cham_hash', 'kv_updated', 'revoked_attr']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Validate the chain beforehand
    if not blockchain.valid_chain(blockchain.chain):
        return 'Invalid chain', 400

    # Forge
    original_block = blockchain.chain[int(values['block_index'])]
    index = 0
    for tx in original_block["body"]["transactions"]:
        if tx["cham_hash"] == values['cham_hash']:
            # key = list(values['kv_updated'].keys())[0]
            key = values['kv_updated']
            if not key in tx["data"]:
                return 'key does not exist', 400
            if key == 'random':
                return 'key cannot be the random field', 400

            original_data = tx["data"]
            if not 'random' in original_data:
                return 'random does not exist, this block cannot be forged', 400
            else:
                random = original_data.pop('random')
                updated_data = original_data.copy() ## here must be a deep-copy

                ## ctUpdate and obtain CT'
                C_json = {}
                CS_json = {}
                D_json = {}
                DS_json = {}
                for field in updated_data[key]['C'].keys():
                    C_json[field] = blockchain.group.deserialize(Conversion.str2bytes(updated_data[key]['C'][field]))
                    CS_json[field] = blockchain.group.deserialize(Conversion.str2bytes(updated_data[key]['CS'][field]))
                    D_json[field] = blockchain.group.deserialize(Conversion.str2bytes(updated_data[key]['D'][field]))
                    DS_json[field] = blockchain.group.deserialize(Conversion.str2bytes(updated_data[key]['DS'][field]))

                updated_data[key] = {
                    'C1': blockchain.group.deserialize(Conversion.str2bytes(updated_data[key]['C1'])),
                    'C2': blockchain.group.deserialize(Conversion.str2bytes(updated_data[key]['C2'])), 
                    'C3': blockchain.group.deserialize(Conversion.str2bytes(updated_data[key]['C3'])), 
                    'C': C_json, 
                    'CS': CS_json, 
                    'D': D_json, 
                    'DS': DS_json, 
                    'policy': updated_data[key]['policy']
                }

                blockchain.maabe.ctupdate(blockchain.GPP, updated_data[key], values['revoked_attr'], blockchain.UK['UKc']) ## Overwrite the old data

                C_json = {}
                CS_json = {}
                D_json = {}
                DS_json = {}
                for field in updated_data[key]['C'].keys():
                    C_json[field] = Conversion.bytes2str(blockchain.group.serialize(updated_data[key]['C'][field]))
                    CS_json[field] = Conversion.bytes2str(blockchain.group.serialize(updated_data[key]['CS'][field]))
                    D_json[field] = Conversion.bytes2str(blockchain.group.serialize(updated_data[key]['D'][field]))
                    DS_json[field] = Conversion.bytes2str(blockchain.group.serialize(updated_data[key]['DS'][field]))

                updated_data[key] = {
                    'C1': Conversion.bytes2str(blockchain.group.serialize(updated_data[key]['C1'])),
                    'C2': Conversion.bytes2str(blockchain.group.serialize(updated_data[key]['C2'])), 
                    'C3': Conversion.bytes2str(blockchain.group.serialize(updated_data[key]['C3'])), 
                    'C': C_json, 
                    'CS': CS_json, 
                    'D': D_json, 
                    'DS': DS_json, 
                    'policy': updated_data[key]['policy']
                }           

                # updated_data[key] = values['kv_updated'][key] ## Overwrite the old data
                random_new = blockchain.forge(blockchain.ch_sk, \
                                            json.dumps(updated_data, sort_keys=True).encode(), \
                                            blockchain.group.deserialize(Conversion.str2bytes(random)), \
                                            json.dumps(original_data, sort_keys=True).encode()) 
                updated_data["random"] = Conversion.bytes2str(blockchain.group.serialize(random_new))
                blockchain.chain[int(values['block_index'])]["body"]["transactions"][index]["data"] = updated_data

                blockchain.chain[int(values['block_index'])]["header"]["transaction_hash"] = blockchain.hash(blockchain.chain[int(values['block_index'])]["body"]["transactions"], 'tx')

                # Create an engraved transaction
                sender    = "ffffffffffffffffffffffffffffffff"
                recipient = "ffffffffffffffffffffffffffffffff"
                data = {
                    'block_index': int(values['block_index']),
                    'tx_index': index,
                    'random': blockchain.hash(updated_data["random"], "random")
                }
                print('check block 0 before: {}'.format(blockchain.chain[0]))
                mined_index = blockchain.new_engraved_transaction(sender, recipient, data)
                print('This engraved transaction will be added to Block {}'.format(mined_index))
                print('check block 0 after: {}'.format(blockchain.chain[0]))
                # Validate the chain afterwards
                if not blockchain.valid_chain(blockchain.chain):
                    return 'Invalid chain', 400
                else:
                    return jsonify(updated_data), 200
        index += 1
    return 'cham_hash does not exist', 400


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port)

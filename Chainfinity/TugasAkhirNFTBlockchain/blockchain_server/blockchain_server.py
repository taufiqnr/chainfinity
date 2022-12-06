# Import
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

from collections import OrderedDict
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import json
import binascii
import hashlib
import requests


MINING_SENDER = "Sistem Blockchain" # Notifikasi blok baru
MINING_REWARD = 1
tingkat_kerumitan_mining = 3 # menentukan tingkat kerumitan


class Blockchain:

    def __init__(self):
        self.transaksi_nft = [] # daftar transaksi_nft yang akan ditambahkan pada blok berikutnya
        self.chain = [] # data blockchain_server
        self.nodes = set()
        self.node_id = str(uuid4()).replace('-', '') #membuat id acak untuk alamat komputer

        # Genesis block
        self.buat_block(0, '00')

    def tambah_node(self, node_url):
        """
        untuk menambahkan node baru
        """
        # Cek node_url dalam format yang benar
        tambah_url = urlparse(node_url)
        if tambah_url.netloc:
            self.nodes.add(tambah_url.netloc)
        elif tambah_url.path:

            self.nodes.add(tambah_url.path)
        else:
            raise ValueError('URL tidak ditemukan')

    def buat_block(self, nonce, hash_sebelumnya):
        """
        menambahkan daftar transaksi kedalam blockchain_server
        """
        data_blok = {'nomor_blok': len(self.chain) + 1,
                 'timestamp': time(),
                 'transaksi_nft': self.transaksi_nft,
                 'nonce': nonce,
                 'hash_sebelumnya': hash_sebelumnya}

        # Reset daftar transaksi_nft
        self.transaksi_nft = []
        self.chain.append(data_blok)
        return data_blok

    def verifikasi_digital_signature(self, penjual_public_key, digital_signature, transaksi):
        """
        Verifikasi signature menggunakan kunci publik (penjual_public_key)
        """
        public_key = RSA.importKey(binascii.unhexlify(penjual_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaksi).encode('utf8'))
        try:
            verifier.verify(h, binascii.unhexlify(digital_signature))
            return True
        except ValueError:
            return False

    @staticmethod
    def bukti_validasi(transaksi_nft, hash_sebelumnya, nonce, kerumitan=tingkat_kerumitan_mining):
        """
        Cek jika nilai hash sesuai dengan nilai mining. (proof_of_work)
        """
        bukti = (str(transaksi_nft) + str(hash_sebelumnya) + str(nonce)).encode('utf8')

        h = hashlib.new('sha256')
        h.update(bukti)
        ekstrasi_hash = h.hexdigest()
        return ekstrasi_hash[:kerumitan] == '0' * kerumitan #

    def proof_of_work(self):
        """
        Algoritma proof of work
        """
        blok_sebelumnya = self.chain[-1]
        hash_sebelumnya = self.hash(blok_sebelumnya)
        nonce = 0
        while self.bukti_validasi(self.transaksi_nft, hash_sebelumnya, nonce) is False:
            nonce += 1
        return nonce

    @staticmethod
    def hash(data_blok):
        """
        Digunakan untuk membuat hash SHA-256 pada blok
        """
        # PENTING!! Pastikan urutan dictionary, jika tidak maka hasil hash akan tidak konsisten
        urutan_blok = json.dumps(data_blok, sort_keys=True).encode('utf8')
        h = hashlib.new('sha256')
        h.update(urutan_blok)
        return h.hexdigest()

    def update_blok_terpanjang(self):
        """
        Mengatasi masalah antar node blockchain dengan menggunakan blok terpanjang
        """
        daftar_nodes = self.nodes
        chain_baru = None

        # Mencari blok terpanjang
        panjang_maksimum = len(self.chain)

        # Mengambil dan verifikasi '/chain' terpanjang dari keseluruhan node dalam blockchain
        for node in daftar_nodes:
            response = requests.get('http://' + node + '/chain')
            if response.status_code == 200:
                panjang_blok = response.json()['panjang_blok']
                chain = response.json()['chain']

                # Update panjang_maksimum
                if panjang_blok > panjang_maksimum and self.valid_chain(chain):
                    panjang_maksimum = panjang_blok
                    chain_baru = chain

        # Mengganti dengan chain atau blok terpanjang
        if chain_baru:
            self.chain = chain_baru
            return True

        return False

    def valid_chain(self, chain):
        """
        Cek jika blockchain valid
        """
        blok_sebelumnya = chain[0]
        # print(blok_sebelumnya)
        # print(blok)
        # print("\n-----------\n")
        current_index = 1

        while current_index < len(chain):
            blok = chain[current_index]
            if blok['hash_sebelumnya'] != self.hash(blok_sebelumnya):
                return False
            # Validasi Proof of Work
            # Hapus upah transaksi
            transaksi_nft = blok['transaksi_nft'][:-1]
            # PENTING!! Pastikan urutan dict sesuai
            data_transaksi = ['penjual_public_key', 'pembeli_public_key', 'objek_jual']
            transaksi_nft = [OrderedDict((k, transaksi[k]) for k in data_transaksi) for transaksi in
                            transaksi_nft]

            if not self.bukti_validasi(transaksi_nft, blok['hash_sebelumnya'], blok['nonce'], tingkat_kerumitan_mining):
                return False

            blok_sebelumnya = blok
            current_index += 1

        return True

    def kirim_transaksi(self, penjual_public_key, pembeli_public_key, digital_signature, objek_jual):
        """
        Menambahkan transaksi kedalam daftar transaksi jika digital signature valid
        """
        transaksi = OrderedDict({
            'penjual_public_key': penjual_public_key,
            'pembeli_public_key': pembeli_public_key,
            'objek_jual': objek_jual
        })

        # Membuat tanda penyimpanan blok pada node tertentu
        if penjual_public_key == MINING_SENDER:
            self.transaksi_nft.append(transaksi)
            return len(self.chain) + 1
        else:
            # Daftar transaksi yang ditambahkan dalam blok
            verifikasi_transaksi = self.verifikasi_digital_signature(penjual_public_key, digital_signature, transaksi)
            if verifikasi_transaksi:
                self.transaksi_nft.append(transaksi)
                return len(self.chain) + 1
            else:
                return False


# Memulai Blockchain
blockchain = Blockchain()

# Menggunakan Flask dan bertukar data dengan CORS
app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    return render_template('tabel_blockchain.html')


@app.route('/konfigurasi')
def konfigurasi():
    return render_template('konfigurasi.html')


@app.route('/transaksi-nft/diterima', methods=['GET'])
def get_transaksi():
    transaksi_nft = blockchain.transaksi_nft
    response = {'transaksi_nft': transaksi_nft}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'panjang_blok': len(blockchain.chain)
    }

    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    # Menjalankan algoritma PoW untuk memperoleh nonce
    blok_sebelumnya = blockchain.chain[-1]
    nonce = blockchain.proof_of_work()

    #Pemberian upah setelah menemukan nonce
    blockchain.kirim_transaksi(penjual_public_key=MINING_SENDER,
                                  pembeli_public_key=blockchain.node_id, # alamat node penyimpanan yang disamarkan
                                  objek_jual= MINING_REWARD,
                                  digital_signature='')

    #Pembangunan blok baru ke dalam chain
    hash_sebelumnya = blockchain.hash(blok_sebelumnya)
    blok = blockchain.buat_block(nonce, hash_sebelumnya)

    response = {
        'message': 'Blok baru dibentuk',
        'nomor_blok': blok['nomor_blok'],
        'transaksi_nft': blok['transaksi_nft'],
        'nonce': blok['nonce'],
        'hash_sebelumnya': blok['hash_sebelumnya'],
    }
    return jsonify(response), 200


@app.route('/transaksi/baru', methods=['POST'])
def post_transaksi():
    values = request.form
    required = ['konfirmasi_penjual_public_key', 'konfirmasi_pembeli_public_key', 'konfirmasi_objek_jual', 'digital_signature']
    if not all(k in values for k in required):
        return 'Terdapat value yang kurang', 400

    hasil_transaksi = blockchain.kirim_transaksi(values['konfirmasi_penjual_public_key'],
                                                        values['konfirmasi_pembeli_public_key'],
                                                        values['digital_signature'],
                                                        values['konfirmasi_objek_jual'])
    if hasil_transaksi == False:
        response = {'message': 'Transaksi/signature tidak valid'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaksi baru akan ditambahkan pada blok ' + str(hasil_transaksi)}
        return jsonify(response), 201


@app.route('/node_blockchain', methods=['GET'])
def node_blockchain():
    daftar_node = list(blockchain.nodes)
    response = {'nodes': daftar_node}
    return jsonify(response), 200


@app.route('/konsensus', methods=['GET'])
def konsensus():
    update_konsensus = blockchain.update_blok_terpanjang()

    if update_konsensus:
        response = {
            'message': 'Chain sudah di update',
            'chain_baru': blockchain.chain
        }
    else:
        response = {
            'message': 'Chain lebih panjang',
            'blockchain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/tambah_node', methods=['POST'])
def tambah_node():
    values = request.form
    # 127.0.0.1:5002,127.0.0.1:5003, 127.0.0.1:5004
    nodes = values.get('nodes').replace(' ', '').split(',')

    if nodes is None:
        return 'Error: Mohon tuliskan alamat node yang benar', 400

    for node in nodes:
        blockchain.tambah_node(node)

    response = {
        'message': 'Node ditambahkan',
        'total_nodes': [node for node in blockchain.nodes]
    }
    return jsonify(response), 201

# Menyalakan server
if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)


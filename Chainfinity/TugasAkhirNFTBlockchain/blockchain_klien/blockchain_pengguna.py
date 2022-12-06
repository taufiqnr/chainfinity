from flask import Flask, request, jsonify, render_template

import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

import binascii
from collections import OrderedDict

class Transaksi_NFT:

    def __init__(self, penjual_public_key, pembeli_private_key, pembeli_public_key, objek_jual, harga_jual):
        self.penjual_public_key = penjual_public_key
        self.pembeli_private_key = pembeli_private_key
        self.pembeli_public_key = pembeli_public_key
        self.objek_jual = objek_jual
        self.harga_jual = harga_jual

    def data_transaksi(self):
        return OrderedDict({
            'penjual_public_key': self.penjual_public_key,
            'pembeli_public_key': self.pembeli_public_key,
            'objek_jual': self.objek_jual,
            'harga_jual': self.harga_jual,
        })

    def digital_signature(self):
        '''
        Menandatangani transaksi dengan private key
        '''
        private_key = RSA.importKey(binascii.unhexlify(self.pembeli_private_key))
        penandatanganan = PKCS1_v1_5.new(private_key)
        hash_data_transaksi = SHA.new(str(self.data_transaksi()).encode('utf8'))
        return binascii.hexlify(penandatanganan.sign(hash_data_transaksi)).decode('ascii')

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('buat_kunci.html')


@app.route('/buat_transaksi', methods=['POST'])
def membuat_transaksi():
    penjual_public_key = request.form['penjual_public_key']
    pembeli_private_key = request.form['pembeli_private_key']
    pembeli_public_key = request.form['pembeli_public_key']
    objek_jual = request.form['objek_jual']
    harga_jual = request.form['harga_jual']

    transaksi_nft = Transaksi_NFT(penjual_public_key, pembeli_private_key, pembeli_public_key, objek_jual, harga_jual)

    response = {'transaction': transaksi_nft.data_transaksi(),
                'digital_signature': transaksi_nft.digital_signature()}

    return jsonify(response), 200


@app.route('/ajukan/transaksi')
def make_transaction():
    return render_template('buat_transaksi.html')


@app.route('/lihat/transaksi')
def view_transactions():
    return render_template('lihat_transaksi.html')


@app.route('/buat_kunci')
def kunci_baru():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()

    response = {
        'private_key': binascii.hexlify(private_key.export_key(format('DER'))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.export_key(format('DER'))).decode('ascii')
    }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)

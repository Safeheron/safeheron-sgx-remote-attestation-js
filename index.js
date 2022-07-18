'use strict'

var mpc = exports

mpc.rand = require('./lib/rand')
mpc.vsss = require('./lib/vsss')
// Protocols
mpc.mpc_ecdsa = require('./lib/mpc_ecdsa')
mpc.commitment = require('./lib/commitment')
mpc.common = require('./lib/common')
mpc.paillier = require('./lib/paillier')

mpc.config = function(randomBytes) {
  mpc.rand.randomBytesImp = randomBytes
}
mpc.setNativeImpForPail = function(fastEncryptWithR, fastDecrypt, fastMul, fastAddPlain) {
  mpc.paillier.fastEncryptWithR = fastEncryptWithR
  mpc.paillier.fastDecrypt = fastDecrypt
  mpc.paillier.fastMul = fastMul
  mpc.paillier.fastAddPlain = fastAddPlain
}

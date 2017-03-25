const EC = require('elliptic').ec;
const ec = new EC('p256');
const BN = require('bn.js');
const hash = require('hash.js');


var example_serialized_proof = JSON.parse('{"G":"04e6acd2d48935e5dbe45cdc709523b33088cc765f43e4bf70d542b2c1d4a4e7544ede67d1efe8b3376d5d438eaf23f49a51cbc3a0d922b2c53885de02db040bd6","M":"048fe6ed55b2f2f6e4bb38746de5caf9ca3d0c3ab3bd39f86ee6bcccc4d8d450f9f96ea563a9ae45844667671f19fd98ba33031fa29273c36d69b27cdcd472f708","H":"04d9c8a7641580e9cca78838d0afbba182725117be905ff0498d9daaf39efa724fb1477942b81666ed5fbe57940f1549564819deefc7d27a24850a1694d8703af0","Z":"0429be4a07716b1d47120584307e315ea46aa929c3f2aa48fdd99ac9d3586062c03981dbe2ba8d2b1f718867c70aec77f3a0caed3400f24f363449654072946241","R":"91820766313758960872733821824367018256726753791189588926651185872630155795305","C":"72708061045794318764113581497860336728677743598081579702100827525997798035809","Hash":"sha256"}')


function deserializeProof(serialized_proof){
    return {
        G:deserializePoint(serialized_proof.G),
        M:deserializePoint(serialized_proof.M),
        H:deserializePoint(serialized_proof.H),
        Z:deserializePoint(serialized_proof.Z),
        R: new BN(serialized_proof.R,10),
        C: new BN(serialized_proof.C,10),
}

}


function deserializePoint(serializedPoint){

    //Guessing decode point does the right thing here but haven't looked closely
    return ec.curve.decodePoint(serializedPoint,'hex')
}


function verifyProof(proof){
    const cH= proof.H.mul(proof.C);
    const rG= proof.G.mul(proof.R);

    const A = cH.add(rG);


    const cZ= proof.Z.mul(proof.C)
    const rM= proof.M.mul(proof.R)

    const B = cZ.add(rM);

    const hasher = new hash.sha256();

    hasher.update(proof.G.encode())
    hasher.update(proof.H.encode())
    hasher.update(proof.M.encode())
    hasher.update(proof.Z.encode())
    hasher.update(A.encode())
    hasher.update(B.encode())
    return hasher.digest('hex') == proof.C.toBuffer().toString('hex')

}

var proof = deserializeProof(example_serialized_proof);

console.log(verifyProof(proof))
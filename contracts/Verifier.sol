// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x0296e7ab7a323d6003af8d20aa045b159ff51633b360cdaf2cd89d0bee11f32d), uint256(0x00249a8524f032aec6fb6b260973fa1c285a1ec5fbeae5bf13afb4282f20684f));
        vk.beta = Pairing.G2Point([uint256(0x281d49ca6821c42403167325e038d134fbf768a8ebac7ffb449c22bac9952280), uint256(0x24f802b1a2187ffe8b3b0797cbc3e24b9189c8514b26fa281f816e98b55fda11)], [uint256(0x1924a21a1afa449d9b71d4d3b35149118256b246b72e390ffbbe4c7a56088ba9), uint256(0x2c70bc1283a24460cb209927db29b60f1e50ef48ed9fe9f3c5ba678a0817c3e7)]);
        vk.gamma = Pairing.G2Point([uint256(0x12d81aee74358ccc1a0bd25219f7b827a807c52b91caa7cbf94dd5ca5cab89bc), uint256(0x0d558b8f35eeeaddb32393a7e96b660568a5385a43e448b222a3a316557f1ed3)], [uint256(0x10293b6737d66970144d012a1058714b881667d65a7e495babd3d504f7e1e94b), uint256(0x25186ae820c0dde9b44a1d1558ea501bde0b845d641e337459618bd12f1e78ac)]);
        vk.delta = Pairing.G2Point([uint256(0x1ea3f0d5f2fad670e93500165207d607071af24ee885c01b990da5894edbeba7), uint256(0x1361482e9cf3a86de9badc3cc7f329ec6bcb3d004ca8bd977b5c9278f4c6d0fd)], [uint256(0x07bf408eee260229f9d6582ca1f76e79c753c239c5002949ed6c2a3695c1f801), uint256(0x056fa3de343c945bf921d72572e8a471cd812284311a0abab18a2d414e3cce0c)]);
        vk.gamma_abc = new Pairing.G1Point[](103);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2d8d46baf5520de07c53a23f364450a9d1b2919d5106848cbf7e43f1cb200bd9), uint256(0x1b94d1c5b23ea014cfe8256374f242de038eb8b23f9a654b76fc8f177cb28df2));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x15769c72c307a0b1b4477942dfc671fa058b9c909a0ded2cbfc30f1343baf872), uint256(0x25db04f119fae5f3e3109bd892e25a2f2f4615d905989d2db4a20db3ed6ff664));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1b15b3d6815079c6e7bbc591e286e8a6da3318b6202734729b1df8da75d6d34a), uint256(0x28261e780b673454691d22f2777a85d7ca7b233d48b37a239a3830484216050b));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x27ccb48626ca40772d47c18e6d80d25ca40396889df877b4134e2914349089ff), uint256(0x02b76a3f081dcd0b113040451f7ab4ad7f30c030108ece54cc8dc6a27de203e9));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x28d61439e17407c3780cfe204eafe4a0087d948fdcef917027c163d7a4421380), uint256(0x13c3b585bfe1b03981d5ad790581ac8ecbc63cbb9727d192fa3a534e1f89c0e2));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x11a60646e2231c058db8532e05565227b989055a1d798768444d09dbad48aa72), uint256(0x27a794dd2439524f396ae8dbeb983703f763ce5d6e27cca54f2d6e9eb8f1dd99));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x060e534b576647b3066f93d738336b9a06c150ca54a99845eb92f64116661b32), uint256(0x2826b9f173fc2ef1a7c0ebfea3008a957ab52d514fc1203eef470d82a1fe39f2));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x19eb3f691797e904d59e6187551e32e06cd18e7614064a677fde4ce9c8d6f90b), uint256(0x170c75a9d48629f66876e5886a91f417e943e3e49c2d504d157edd8ba233effb));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2a16a1b014248c49cd73ef38af62d8c28f6d4d82ab7f89a78437c8798c64c0c2), uint256(0x2bb9ee012920df72919fcef356e6d426bd96ccd06ed28edb753ac0e696d25813));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x12e2136a5c95c5c610c541e08d71aae91072aa3521eb50850a21e96d4a0ad897), uint256(0x07871aa1622a74d12aafd6a797fbef10211e3294bf44b03bc8993094313fb6dc));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1421d596bc1e0b36b79821cfb48987db5b7fb3b3ed79c3e91f5d5e954dbfc2e7), uint256(0x164491c9a1887ba8306ed100c997ec6bf39763f70069f64d1b5443a791994200));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x06a607984f5a148cbb8a7de42c493cb11e95bc0dbb43179a5f00aa418b04308e), uint256(0x1fb048f01d907529c9fbe2839c6c3135bd771b94f7fbf573e88e657533214682));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1b7daef2c9a6c9d2f398a2d8c1e5fb94ca1836812af9cf5e59995aedb45e39d8), uint256(0x032818798a09d720f78af16783524fdff8d5728a71d4f9f1378a12e210ccbf9f));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0a6818ff54ee120e5370ffac26f418beb808b22d7242c7f4b517739de2f4f2ac), uint256(0x23a61d0c0e6c0a2b918218046d9ed5d06824cd06aca6a4cf07ba1b16b60f81c7));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1c50a37c90f83dde7537af6b9d633f000ea3bde4cddace61fc7a214a070cda02), uint256(0x051ee42cc5ee0c78e19cbae3b27e4e82c4b0ce93df907725d9097788c43f8108));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0de820fa31a9acaafe03a25fe5a9becc97f795f428d4c65e60f217c2716a4bcd), uint256(0x2d9963255a633c818c9dcfaf85defe74b407240072943a66ff431ce626635135));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2d01299d049fc95c44801cce816536192b6ad74ed4b4d11a68808d9c0cd97a76), uint256(0x236950e09812d60fd034aa4f7fe81c5e8a0c924fa6daeaf3dbfe24d309ce77d5));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0c7435c16ceb141484496bd091fd7c8daecd9947de862515a0ed03c018f2a394), uint256(0x2b00a5e11bef88c34ffbae387f063ca0338c7a43c04eca21d9ad2abba3eae5cd));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1ea1c01069d761f5784d44a60f909ff81759b88fc65a0315792fa0883573ec3e), uint256(0x128f51daaaa579235747002a6ac35903d45e535a5d9385990cfda97240ce2451));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2477b18d53a27f64a4438a5d6aff15b2bc3701223d9b6b45fcac8c527c1ef68c), uint256(0x1a0c0b861ffa7bc29faf42a87a154ed87a809d5672264c4bc16de7c39409eb6f));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1b9f2d64ba7eff2fa8f09eee10a8a70afb55fa79c9a363559f6e2eaddf907667), uint256(0x1e8834d479dfc1c7487b633ca0a6c50b3624a845774cb7fbb671b78893128cc0));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2b136333ec659216188690275ea863a676556443e30b0ab36c4511494b39a8d4), uint256(0x2d10d69409d7b6f448beb45daf159b993f5391a8f3f8fd6e2f016f633b4bb0ad));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1742e2a391e5ad55c267473f05e529bfe3acc6a7fd03c68752fcc7db87bb1640), uint256(0x2f5bddb4ab7597c3a51b1e409e39347d2670722f334d765efa93ee9bc5743886));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x212bc1b07857273ca1323b8bda182bc6fff79c77b62ce50bba49db5a38d954ea), uint256(0x05e6635ed55fd7cc3d08a2db4febd92a4afbd98b42e3a2ca29868919f070b1aa));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1ced2d30f15525d91c6faa724fc94631a6381116e1a86ea6081696217dc18cc7), uint256(0x281310c6db3763878f34868830e4f0ecc30529bfdcd6514dc66400a28b56a668));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x049dc7765a707ffb6963f833016be4069a284b0cd188e31f655f1adaf94fc97d), uint256(0x14a3e74053610ac2331ce1809307b86b5319ac29201562b99567551f154e1080));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x13c2d70b95b4a2091f489a57cf71473e96d4b44f499e204ad4b0e220f34fd266), uint256(0x1909b096e08c36c1ff83e83568cfa0074a8879a274c566f5701207e86f79552a));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x045be28dd50d72de0be88e4377e393c5b6e4c324e60388dd22ba13c17ed1d662), uint256(0x2f7d50a781ae33496a748eff8fb65656b6a6c7d2dc1f397994e9408ed81219dd));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2a58a2d5b26dd485830bf1bb8436fc75616a6c650365269ffe9296eeb544dbd0), uint256(0x0d7d69c1ad2c2bc89b311c82a2193d77e06e7a27e2f9625c81718003dc413abd));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2795e2510c17d2ed1d39cca173e9b43aaa95150da671e731335ba95d5d7a170c), uint256(0x08e65d7745034172cd64a67335fa15da2c9b8af58e89fa559f0585e771aeff79));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x276846fe70f2a63e72d02d273db671c7e9c3cc1db31d256e616128282b3890ed), uint256(0x2709d60979621ec4bf843256c869649e0a2dddf39c9d03d2b72e0d92c039606f));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x05fc0d621012f2cf85285bfe8d87ce3d4c73492877bf59fa83dcd5d916257bde), uint256(0x2be9eb0138f7230f61bbc22bf2a32bd0ae8152da370ba2213991f4abdba729c3));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x07c2edf0b67123b631a974dea2be98a412093bb9333683bce247f11f6f799c63), uint256(0x0e51384e0b38f6a776bb4b25b0dff1b90aba31f8549a825e0c410d831228b403));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x304f3ea1792b592ba3c8efbbc22041e632fb171b1cac8c5f5bb240a9acc97985), uint256(0x2439f549242390943a1dbf48788ad65e017dfb1de09791347c46f4d7d6a36854));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0b24aa4eac6ee1a5dadc5a64ca3069ea5c65fd545fa1235cb7f74165bacd89fb), uint256(0x1f251a86ee95a3cd1be8c4f398cc76ebd2dfd71f29392c551fc1d3c001b39fef));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2af7968114e25ca09724ede06496cabbebc84ea24beba98f7997f8db96da0ed3), uint256(0x018f76d1062809708ac66d9827e6b588b4b37521a84f294e49bee384dfe6788f));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x191875af0bf897dc07a52ea63a5ef3d60a0156db0d2c2823193a19c7d416aba7), uint256(0x215981b7e40fec8822eda804069d27b90c652d7b01af8c90504866b7f5944f5d));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0de7e04f9512de05b2e4f1823fe861709d342f60b64c9165c2bd10f454751719), uint256(0x1321e63aca15ce78ea214213baa0e5fe488c32e42055cf24cc8208a67633c413));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x28d78e5e8fee721db7f213439ee27af1b86ee50b0a9393222413b0ae43bf9a67), uint256(0x2a6f12e0dccdc167335f6b2cf408e971ec7e2723eed76a94294c41de20765f3c));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x1e9f1fc890a43675076ad95cc91f3b84e86158cdeb50af88cb340764f3599209), uint256(0x07ab031c7b0a5560106b7bc09a7458702822dc0e21d239d0076e6cec7aa0d83d));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x13b1a9b4c3e4f586f88cdc86ccbab5b6b327eada8f4466caff408423ed2abfd7), uint256(0x1abc0daa92afa897022126d9bb6bafdb5273591aafe9defe4bff1eb6950c12ad));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x297262dcb993df2e1f9de04a930efc85f18a43eeb6148296bd19f588fbbac54b), uint256(0x113d3961b19ca171f41a050f9ece9b5face247e3f03eb54af37ed49b962db820));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x093bf4652c3f681a4a874d7b6ac44b382620c50892067705d1847d3455713581), uint256(0x07be2605ebf793e58e708425005604124bf19f81a0f64fa74a34647dcbc01f2c));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x16856f785fee705ff81ee7e7517d9aa70d3a0c030bc82039bd404b32ee3646bc), uint256(0x0f027e5a8ddd022b9941832a3d585acfe0b6042afddb20c890c43e23ad35e58c));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x1721878f73804873788956a0b4300f1d033d0a8da2d3ee1498b6def570f9cd9e), uint256(0x26d04cf23bbef7ed78e8b55088d75eac2ebedab5367583ef378e76b5993ce79d));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2c1593b7f8de1f084a70fd12d7d6a4a7254d7ef716394ae9f5b4d6157b9020e3), uint256(0x192f8ac26af7a8c77e9059e9ec1d004534d945e880adb1b6a6806835fdc40ac8));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2476c7c1e9719173686d36e145912a689806a7241d1f1734f6eb5d85ecc56d34), uint256(0x0ebd54f467f767863eeb2a446737be1201d1bc4057ed2c18db7dc3fce148b8c3));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x24b1325cdc0a0c1879d600edd6bc233ae9aa101f370dcd3563fa1409316319de), uint256(0x02da0644daafb3eaad64945967c0695f18b73d13ec802797b5bce6b1594adb8e));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0d8b82006a8dd8cba1b8d58702ebd9eacb827adfc33a1883770193c4ff18bb0f), uint256(0x135eaf5d695398c5ba0c7b6976dd7d7993a3fd6438871e404ae8243d473a60a6));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x304750e62b670c3ad9a37dedf004e5814edb49a0d8f39156466b53d45e026cda), uint256(0x1a807580c2f3d0ce0f5e6cd085e463e08e9ef5b3977da818ce0ad3a57eecc0cd));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x23ac46c066fc9fedfe4b0191cd29298176900918ef358232a3be374f997861fe), uint256(0x2f371d327962243418bdcf27ed1d0a31020260f82e332f7ae3588abf115afde8));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x073e008ceea7ad63779647dbe543ef2d3016f04036299940f8cd16c5b269f730), uint256(0x047a6fa7201aa8b57d70dc725e63bfce907a1e65815037b4c519197bb670cba2));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x03f99e5fe75a09d6d1e9670932344fc262be15698a55e015a52f1d517fbaf5e0), uint256(0x167be7554a5bc818a5f763190a565559a91ea245bd209b94d5aff167ea1787db));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x066cc5f9c61659eb95e3576c2b7a9de9a6eaa9def6dfa19336d4ff4668636542), uint256(0x249421143dd342d4f2d4a88b7fd2b0b986440c0027b9153ed2c6649174b31a1e));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x1ed771a1219b610cba5b176bbac931e3d8e8139d0dfef10b7271d41a4adf880d), uint256(0x05bc2f8faa1acfd808974b850de748c7fab349cd1a14804d57f096b32274bf90));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x0cdad641b2118209fd8576a72415b04df3bbfc6417248059c4d05633511a2ebf), uint256(0x189aae274774aa45707ded557c83594af999967069e4b95dac3edbc9f1217104));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x29654c07ec89aeb6b5a4382bd80ba78ed5d2b498f71d228a9b0f704cc1508836), uint256(0x25d2b05b6e594fa9c80b195df440fa32d1adf0611f94a379125d6e9ab3698312));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x1282e96630bf3471d7dfd4390ae87d1e84cf4a3762892e9f5196ff523b7e2dee), uint256(0x1292e52b150835367f87bc1cdd0f1245b8035a4aece91ba3b8f76afe7364991a));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x004b6b3a8258f4b1abb86938e1b6054fe33ae4f25d22ab660b08e90c5f3d466a), uint256(0x2ae0885b222b9532bba83af9fa2f916158b7d77a42aff7121c5b6d70f67e2120));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x0be80a5a91aebef7569f904c9ecbd99caddff6b219e2a11899515ff0562c4f61), uint256(0x093bf197daf4a290f162a08bcbb4bc76380fae9fe4b48da72ac5971cefde73b6));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x22f9e84ed7616e78332e7cdd0732f88cc96140f123e3181ab7bc264302e2b50f), uint256(0x274965913f493a2044ac0dbbf8a463ba2003d0f457bc44392f2cc0546e0063df));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x07817dc6ccbb71d1e9396b577664b85ba08b133b5568882dcbbfeadf4d40edb2), uint256(0x157595c0f6aeef8e99b59b5378377bc31eda6f6ff7137f75101030da375c2118));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x038ff10812e0fbfebcc747059feaffb31ca42046495605616416bfdcbae2c412), uint256(0x0f4fe8422de2e5608def2536d3a238f9db9c071f457240422b6985ebd3ce4900));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x2062cbce948f7de114c3f58f3dcddc8184ceb2e1d153e4cbad11d94ba6935dca), uint256(0x2ea6ada0638a2cd579d5891863ed70f98a6ae053c1829cf60abf24d9fb817c29));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x1ac72bef8b1246dfa6285b50e879b9f87866f3ef17ecd3b999926b0bf05587f0), uint256(0x2202dd9b668f286728292f79dd06380a2ccfae6c13288ee3ac15327b3fafebaf));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x0d6a6a5076c5251df5372e9fd6aaf6121a24b28ddae98ebbb9558d69bafe44c5), uint256(0x20ef9601f0b0683658ee19e33a47e2202f0e7160a6d93e17262ffa489b46ed83));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x002e910f29529485983856a471a854947af7d9a157fd238598ff8d61e4c7ba3a), uint256(0x0fb0bbe26101aeec7bab2e063af1c70310f2c51a468c296289d67a438a4d9aa1));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x2631ba5fd9734349272284e8435e69476270aa0d4087b1a41987fb96c52ce49f), uint256(0x2d56b3fe0f198376f771975ba12b4577cd97376aef75c6af4ddfb4a945cecd47));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x25cb706d6f08166a07a6b6f1705b02b4b7abf6e30a55c45b4da33f87b64149be), uint256(0x1502eb66bbfcfdd5890afe3b4bd650a2c027f6c53fa05c738ae300a322be1df4));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1ecb959cb6e4605babb0f4e566c4cfc5dc4b7cfdc8353f4a28fd789bed6017d3), uint256(0x2c4c2d3ddd66e16ec69e65458f020b913b7c008344e6e1582a5afca5399cd18e));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x12b553053cb1f8a7f72bad28b53358e50d7e5e919dc91ac8caadfdee50789726), uint256(0x1aa6ccb5dfb83ec03951186add0955eef245b7c48da704e9b4f5f87abae42fa6));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x0e77c7116fa85d23fbce4b4f91a28c2a687ca24475c65f2a656cfb879d934ddb), uint256(0x0f358eab430b68944580d0d7f6e9ecc22ab08a658c94c3d6e1b089a38377f472));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x2db975a1f245539efa7ff25f1ba22c9e88b0710ee67ab52b63eba77985a93ae1), uint256(0x22d1129527912cd4181dde10da7bd9940e53fb9df8d165dfc3a12e8580113ee4));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x02b76d7be0d95200dd59a41e12d799d1a1e61ce5e03ab79c1279566e3589ae07), uint256(0x029816c8d980f07e2d1d937ec3c52c439d5d82ab28df0bf31eb956895c7353a8));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x133a105b86fe48e0faa127492b0575f18c9d373f164c12ab4d26bc0ff9b6bb07), uint256(0x28503e2a7f77c3316c4324c3436ead944c69e37fc1510e778ee61567e475d86c));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x2a6c30885e99c31e29b7923c9950d75138a4030c2d5a483b5db7658d91f0fe5a), uint256(0x0477817b608bb5bd4c56bb4b136eb2a9afafa92c2075069aeb63a4eb54e860e4));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x24d51bb25cc4e6ad137e3dd792400c7e10b579269b5f524139d5c07a3050e345), uint256(0x205844174473cfd06b96c2875035d56954808c12cfe0034498bed802ef6bcc31));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x1d6f8d1f4538c894fae86b4ae09d88b8d7ff347b0ee9cb7aeefc0ed6f59de23b), uint256(0x285c1b0557d32b765fe145b2d15b6862cce7ba4d8cc02839d81fca37b8fbdd90));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x178e4d1e3997644091fc068876cb4fad8fd10082c2d766d260d2fcf989dec640), uint256(0x2ab6108fdfe18d63196b3a244bd9c1f02d3cb82d264dc933447fd16b3ff371c6));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x14f0875d4aa12c77aa18ca47bc2d8b1da932aec7c63803743e431bb6e04113bc), uint256(0x2464937d4e322da26bd00a2dbc4ab5d8ef4fd21fe82e81ce77d50c18925b6055));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x1b2869639d2d601ff1d1455bf4e6c1656e4ecda4675961670ef1413c50b81cea), uint256(0x29c89a410fc607973fad2902b421957db0ccfd90b526755d27dc2904214237be));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x24ee5b3131ef435955341e49d036e300a2a09fa87c9ea6450e1f326df96d8817), uint256(0x23a7d0cee2b5fa938de24ab40d32ec8dba08682005744da77adcdde37151002a));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x0c195a88a8ad992ce587a2cd97cc8b033120678f172e528bcbce23144cfc9150), uint256(0x19e4176fab392e13c8e7ee5507780ef57a5a56ca728f452a7a40facab9973b4a));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x15a9f4f7a11d058225a6b6da02e3d10d85a800866960dc7ba1867d2600a0c14f), uint256(0x092facfe15000eedeb0085c31d32c9188f64ba026c9256420c8f2be543f6f39f));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x09f08ce3bbc0c8f807aadfc4fde40213bc7f7b2ffcbb751ac3b37f0f0ff9f949), uint256(0x1adee5fa436bd409c4aa6dfeab3a04704d52216585945e1404bd696221fb03f9));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x1e3db970cbcf96fcc104c7c87ae44defdb791de06411e299a43dd45d9b706c74), uint256(0x23e5ae9350772cc7d7c6e1b038df2af597a7f3edad653f5b39601ae07ef51f17));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x0bdb71d1aec02633eebd6127d092791e6f326b00c66c2c21b929a1dcf580c7a7), uint256(0x2cd49ce6994741fd11bcd9a7c6a6c90ef199ca8440e0c16e1655adde2df8708c));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x2a7d4f424ddf8be9eb17ee8db77967ab93295f0e2a832b4f93b4d76d1ebec258), uint256(0x117805c914ae63dd3459f76fe55f82a42fb64ff8a6f6028c7b0b30f801c69393));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x22b5ebb928a11c3bd3cb7dcd6c5cc70da592dfffaa9182e29badc5256bbd3e64), uint256(0x2916c854463427956a91ab5105d7b4314ed3a7007904a113df29c74c603f9946));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x2ee12e4457cff25b5c0fc4d9b6b39f905c09a0a0ad4b67eb79e80e98e1e70840), uint256(0x1372abb5272973d30a8208e1a171925cdddad2609e0477ae43b4345f943878a3));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x2dbe213310f21103b92a5e463c689e3c39d875983d82f8074c86d69efead01aa), uint256(0x0b946515ce2829e2c1746c647cedf4b7d1524ca30635459f77670756bf2391ae));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x12617b03017a71fcf89060167887c04b9d93070bd185199586bb775e993e28e6), uint256(0x0ca44bdfa54e0388e364c916c80f180b2ebcdf95af30478c8838860e027f0c90));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x21907af688c7d04418286837a6279aabd08c866627c41c22e429e6f1cb2732bd), uint256(0x277dbca17750d1dd3db63bd2f313f36a04f30326e68b7f2be1f6e59083011f76));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x0f1541105d3a7fc034871a4b253bdb0ac44bcd88edaafa4926bedce8ee70e4e3), uint256(0x1016a02b762f6b51cbe592e4e36fc6af4368d302c53ce9ad830626528de7a935));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x24ce1c9ac973124c6c0ab042fa5f00d515c4a496acde2b5913cee2b18584e822), uint256(0x0372d758d7af4b12d8c7c6b27ed471661b93d8d7657c6e6ed1d95f8d0dd90e1e));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x1594224b272e623888c82d14c78d7b8ceb1efdb4a129d39de9c6c6f2de3a8e3e), uint256(0x128b3a3ab05047785f5b01d4089849c3517e58686ae49339229f15cdc78f4f27));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x305fa5e3ec3c2881da631d4f5066e373bbfb49aadc4c027c6d3d2fac18721339), uint256(0x1275092c96572801bfc34ba7b966738a2095b49b5230f5142aabc4971fd46b80));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x0535a1573504a0ada63a038dc534e406cf0ad82a79c246957d2cab4e8afb5afa), uint256(0x20c9d765661d24cff98d5d211a9910be24967ba2342fd2bcd2102e452c4011c8));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x2000c3cbc23933babf1de1836778d34a7fb17c6c2c2b9a9e7b65ae20f11e6294), uint256(0x2d190f562c10cfbd0dd506aa613e46c32876ea9f4da496c0e3d367c10f20d92e));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x2b0dd451aadb5c88af01d1f3f890c9752a417c7eeed38713fa7d887e3a228f44), uint256(0x1e6e4e9c9324c4d752f1985ffc27c6972ce2accb7d134c8f4525523116d9818a));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x1e9da012f9165731608531a80c44fff138d9cb81f4cbd866415100d1cc1fa3ec), uint256(0x0740bbe061c72e6127a69681e7a79109adb33a1f61c9527fc8d0fbb97aff80c9));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x0766ce0a42b361bc565382406e36052866f71cee42af05554c410c86c9b830d7), uint256(0x25484dbc9f252d28cb8bf080581f986426426e912e41a28e7cb57034649cfdff));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x1b7f279c9cd5d88fa2d98e6a69e34700b4adaddcc06889d403b34ffede2f95b8), uint256(0x17f1a9add557521c58f1890de5cd1611d974ec9d4530231ef35136156efebbf0));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[102] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](102);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}

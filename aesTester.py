import unittest
from aes import cipher, inv_cipher, expand_key


class AesTester(unittest.TestCase):
    def setUp(self):
        pass

    def test_a1_128_key_expansion(self):
        print "(A.1) Testing 128 key expansion... ",
        round_keys = expand_key(0x2b7e151628aed2a6abf7158809cf4f3c, 4, 10)
        # we will just check the final column of the last round key, that's good enough
        self.assertEqual([0xb6, 0x63, 0x0c, 0xa6], round_keys[43])
        print "Passed"

    def test_a2_196_key_expansion(self):
        print "(A.2) Testing 192 key expansion... ",
        round_keys = expand_key(0x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b, 6, 12)
        self.assertEquals([0x01, 0x00, 0x22, 0x02], round_keys[51])
        print "Passed"

    def test_a3_256_key_expansion(self):
        print "(A.3) Testing 256 key expansion... ",
        round_keys = expand_key(0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4, 8, 14)
        self.assertEquals([0x70, 0x6c, 0x63, 0x1e], round_keys[59])
        print "Passed"

    def test_b_128_cipher(self):
        print "(B) Testing 128 cipher... ",
        encrypted = cipher(0x3243f6a8885a308d313198a2e0370734, 0x2b7e151628aed2a6abf7158809cf4f3c, 128)
        self.assertEqual(encrypted, 0x3925841d02dc09fbdc118597196a0b32)
        print "Passed"

    def test_c1a_128_encryption(self):
        print "(C.1) Testing 128 cipher... ",
        encrypted = cipher(0x00112233445566778899aabbccddeeff, 0x000102030405060708090a0b0c0d0e0f, 128)
        self.assertEqual(encrypted, 0x69c4e0d86a7b0430d8cdb78070b4c55a)
        print "Passed"

    def test_c1b_128_decryption(self):
        print "(C.1) Testing 128 inverse cipher... ",
        decrypted = inv_cipher(0x69c4e0d86a7b0430d8cdb78070b4c55a, 0x000102030405060708090a0b0c0d0e0f, 128)
        self.assertEqual(decrypted, 0x00112233445566778899aabbccddeeff)
        print "Passed"

    def test_c2a_196_encryption(self):
        print "(C.2) Testing 196 cipher... ",
        encrypted = cipher(0x00112233445566778899aabbccddeeff, 0x000102030405060708090a0b0c0d0e0f1011121314151617, 196)
        self.assertEqual(encrypted, 0xdda97ca4864cdfe06eaf70a0ec0d7191)
        print "Passed"

    def test_c2b_196_inverse_cipher(self):
        print "(C.2) Testing 196 inverse cipher... ",
        decrypted = inv_cipher(0xdda97ca4864cdfe06eaf70a0ec0d7191, 0x000102030405060708090a0b0c0d0e0f1011121314151617,
                               196)
        self.assertEqual(decrypted, 0x00112233445566778899aabbccddeeff)
        print "Passed"

    def test_c3a_256_encryption(self):
        print "(C.3) Testing 256 cipher... ",
        encrypted = cipher(0x00112233445566778899aabbccddeeff,
                           0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f, 256)
        self.assertEqual(encrypted, 0x8ea2b7ca516745bfeafc49904b496089)
        print "Passed"

    def test_c3b_256_inverse_cipher(self):
        print "(C.3) Testing 256 inverse cipher... ",
        decrypted = inv_cipher(0x8ea2b7ca516745bfeafc49904b496089,
                               0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f, 256)
        self.assertEqual(decrypted, 0x00112233445566778899aabbccddeeff)
        print "Passed"


if __name__ == '__main__':
    unittest.main()

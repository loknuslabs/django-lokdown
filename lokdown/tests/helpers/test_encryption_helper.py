from lokdown.helpers.encryption_helper import decrypt_secret, encrypt_secret, is_encrypted_value


class TestEncryptionHelper:
    def test_encrypt_decrypt_round_trip(self, settings):
        plaintext = "JBSWY3DPEHPK3PXP"
        ciphertext = encrypt_secret(plaintext)
        assert ciphertext != plaintext
        assert is_encrypted_value(ciphertext)
        assert decrypt_secret(ciphertext) == plaintext

    def test_encrypt_is_idempotent(self):
        plaintext = "JBSWY3DPEHPK3PXP"
        ciphertext = encrypt_secret(plaintext)
        assert encrypt_secret(ciphertext) == ciphertext

    def test_decrypt_legacy_plaintext(self):
        plaintext = "JBSWY3DPEHPK3PXP"
        assert decrypt_secret(plaintext) == plaintext

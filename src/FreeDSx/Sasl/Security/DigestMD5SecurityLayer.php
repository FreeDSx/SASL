<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Sasl\Security;

use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\SaslContext;

/**
 * The DIGEST-MD5 security layer.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DigestMD5SecurityLayer implements SecurityLayerInterface
{
    protected const MAXBUF = 65536;

    protected const KCC_MC = 'Digest H(A1) to client-to-server sealing key magic constant';

    protected const KCS_MC = 'Digest H(A1) to server-to-client sealing key magic constant';

    protected const KIC_MC = 'Digest session key to client-to-server signing key magic constant';

    protected const KIS_MC = 'Digest session key to server-to-client signing key magic constant';

    /**
     * RFC2831 Section 2.3 / 2.4
     */
    protected const MESSAGE_TYPE = 1;

    /**
     * Cipher specific details related to the encryption / decryption process.
     */
    protected const CIPHERS = [
        '3des' => [
            'block_size' => 8,
            'kcn' => 16,
            'cipher' => 'des-ede3-cbc',
        ],
        'des' => [
            'block_size' => 8,
            'kcn' => 16,
            'cipher' => 'des-ede-cbc'
        ],
        'rc4' => [
            'block_size' => 1,
            'kcn' => 16,
            'cipher' => 'rc4',
        ],
        'rc4-40' => [
            'block_size' => 1,
            'kcn' => 5,
            'cipher' => 'rc4-40',
        ],
        'rc4-56' => [
            'block_size' => 1,
            'kcn' => 7,
            'cipher' => 'rc4-56',
        ],
    ];

    /**
     * {@inheritDoc}
     */
    public function wrap(string $data, SaslContext $context): string
    {
        $qop = $context->get('qop');

        if ($qop === 'auth-conf') {
            $wrapped = $this->encrypt($data, $context);
        } elseif ($qop === 'auth-int') {
            $wrapped = $this->sign($data, $context);
        } else {
            throw new SaslException(sprintf('The qop option "%s" is not recognized as a security layer.', $qop));
        }
        $this->validateBufferLength($wrapped, $context);
        $context->set('seqnumsnt', $context->get('seqnumsnt') + 1);

        return $wrapped;
    }

    /**
     * {@inheritDoc}
     */
    public function unwrap(string $data, SaslContext $context): string
    {
        $qop = $context->get('qop');
        $this->validateBufferLength($data, $context);

        if ($qop === 'auth-conf') {
            $unwrapped = $this->decrypt($data, $context);
        } elseif ($qop === 'auth-int') {
            $unwrapped = $this->verify($data, $context);
        } else {
            throw new SaslException(sprintf('The qop option "%s" is not recognized as a security layer.', $qop));
        }
        $context->set('seqnumrcv', $context->get('seqnumrcv') + 1);

        return $unwrapped;
    }

    /**
     * @throws SaslException
     */
    protected function decrypt(string $data, SaslContext $context): string
    {
        # At the very least we are expect 16 bytes. 10 for the actual MAC, 4 for the seqnum, 2 for the msgtype.
        if (strlen($data) < 16) {
            throw new SaslException('The data to decrypt must be at least 16 bytes.');
        }
        $receivedMsgType = hexdec(bin2hex(substr($data, -6, 2)));
        $receivedSeqNum = hexdec(bin2hex(substr($data, -4)));
        if (self::MESSAGE_TYPE !== $receivedMsgType) {
            throw new SaslException(sprintf(
                'The received message type of "%s" was unexpected.',
                $receivedMsgType
            ));
        }
        $seqnum = $context->get('seqnumrcv');
        if (!is_int($seqnum) || $seqnum !== $receivedSeqNum) {
            throw new SaslException(sprintf(
                'The received sequence number was unexpected. Expected %s, but got %s.',
                $seqnum,
                $receivedSeqNum
            ));
        }

        $cipher = $context->get('cipher');
        $a1 = $context->get('a1');
        $isServerMode = $context->isServerMode();
        $this->validateCipher($cipher);
        $encrypted = substr($data, 0, -6);

        # Inverted selection of constants here and for $mcKi, as this would be the receiving end.
        $mcKc = $isServerMode ? self::KCC_MC : self::KCS_MC;
        $kc = $this->generateKeyKc($a1, $cipher, $mcKc);
        [$iv, $key] = $this->generateKeyAndIV($cipher, $kc);
        $data = openssl_decrypt($encrypted, self::CIPHERS[$cipher]['cipher'], $key, OPENSSL_NO_PADDING | OPENSSL_RAW_DATA, $iv);
        if ($data === false) {
            throw new SaslException('Failed the decrypt the message.');
        }
        $message = substr($data, 0, -10);
        if (self::CIPHERS[$cipher]['block_size'] > 1) {
            $message = $this->removePadding($message, self::CIPHERS[$cipher]['block_size']);
        }

        $receivedMac = substr($data, -10);
        $mcKi = $isServerMode ? self::KIC_MC : self::KIS_MC;
        $ki = $this->generateKeyKi($a1, $mcKi);
        $expectedMac = substr($this->generateMACBlock($ki, $message, $seqnum), 0, 10);

        if ($receivedMac !== $expectedMac) {
            throw new SaslException('The received MAC does not match the expected MAC.');
        }

        return $message;
    }

    /**
     * SEAL(Ki, Kc, SeqNum, msg) = {CIPHER(Kc, {msg, pad, HMAC(Ki, {SeqNum, msg})[0..9])}), 0x0001, SeqNum}
     *
     * @throws SaslException
     */
    protected function encrypt(string $data, SaslContext $context): string
    {
        $cipher = $context->get('cipher');
        $a1 = $context->get('a1');
        $isServerMode = $context->isServerMode();
        $seqnum = $context->get('seqnumsnt');
        $this->validateCipher($cipher);

        $mcKc = $isServerMode ? self::KCS_MC : self::KCC_MC;
        $kc = $this->generateKeyKc($a1, $cipher, $mcKc);

        $mcKi = $isServerMode ? self::KIS_MC : self::KIC_MC;
        $ki = $this->generateKeyKi($a1, $mcKi);

        # The first 10 bytes of the MAC block is used. Extract the last 6 bytes, as that gets tacked onto the end.
        $macBlock = $this->generateMACBlock($ki, $data, $seqnum);
        $ending = substr($macBlock, 10);
        $macBlock = substr($macBlock, 0, 10);

        $padding = $this->generatePadding($data, self::CIPHERS[$cipher]['block_size']);
        [$iv, $key] = $this->generateKeyAndIV($cipher, $kc);
        $encrypted = openssl_encrypt($data . $padding . $macBlock, self::CIPHERS[$cipher]['cipher'], $key, OPENSSL_NO_PADDING | OPENSSL_RAW_DATA, $iv);

        return $encrypted . $ending;
    }

    /**
     * @throws SaslException
     */
    protected function removePadding(string $message, int $blockSize): string
    {
        $padOrd = isset($message[-1]) ? ord($message[-1]) : 0;
        $padRaw = $message[-1] ?? '';

        # The padding size should only ever be between these values...
        if ($padOrd < 1 || $padOrd > $blockSize) {
            throw new SaslException('The padding size is not correct.');
        }

        $msgLength = strlen($message);
        for ($i = ($msgLength - $padOrd); $i < ($msgLength - 1); $i++) {
            if ($message[$i] !== $padRaw) {
                throw new SaslException('The padding does not match the expected value.');
            }
        }

        return  substr($message, 0, strlen($message) - $padOrd);
    }

    /**
     * @throws SaslException
     */
    protected function validateCipher(string $cipher): void
    {
        if (!isset(self::CIPHERS[$cipher])) {
            throw new SaslException(sprintf(
                'The cipher "%s" is not supported.',
                $cipher
            ));
        }
    }

    /**
     * Append a signed MAC to the message.
     */
    protected function sign(string $message, SaslContext $context): string
    {
        $seqnum = $context->get('seqnumsnt');
        $mc = $context->isServerMode() ? self::KIS_MC : self::KIC_MC;
        $ki = $this->generateKeyKi($context->get('a1'), $mc);
        $macBlock = $this->generateMACBlock($ki, $message, $seqnum);

        return $message . $macBlock;
    }

    /**
     * Verify a signed message. Return the unsigned message without the MAC.
     *
     * @throws SaslException
     */
    protected function verify(string $data, SaslContext $context): string
    {
        $receivedMac = substr($data, -16);
        if (strlen($receivedMac) !== 16) {
            throw new SaslException('Expected at least 16 bytes of data for the MAC.');
        }

        $seqnum = $context->get('seqnumrcv');
        $message = substr($data, 0, -16);
        # Inverted selection of constant here, as this would be the receiving end.
        $mc = $context->isServerMode() ? self::KIC_MC : self::KIS_MC;
        $ki = $this->generateKeyKi($context->get('a1'), $mc);
        $expectedMac = $this->generateMACBlock($ki, $message, $seqnum);

        if ($receivedMac !== $expectedMac) {
            throw new SaslException('The received MAC is invalid.');
        }

        return $message;
    }

    /**
     * Per the RFC:
     *
     *   If the blocksize of the chosen cipher is not 1 byte, the padding prefix is one or more octets each containing the
     *   number of padding bytes, such that total length of the encrypted part of the message is a multiple of the
     *   blocksize.
     */
    protected function generatePadding(string $data, int $blockSize): string
    {
        if ($blockSize === 1) {
            return '';
        }
        $pad = $blockSize - (strlen($data) + 10) & ($blockSize - 1);

        return str_repeat(chr($pad), $pad);
    }

    /**
     * RFC2831 Section 2.3
     *
     * The MAC block is 16 bytes: the first 10 bytes of the HMAC-MD5 [RFC2104] of the message, a 2-byte message type
     * number in network byte order with value 1, and the 4-byte sequence number in network byte order. The message type
     * is to allow for future extensions such as rekeying.
     *
     *   MAC(Ki, SeqNum, msg) = (HMAC(Ki, {SeqNum, msg})[0..9], 0x0001, SeqNum)
     */
    protected function generateMACBlock(string $key, string $message, int $seqNum): string
    {
        /** 4-byte sequence number in network byte order. */
        $seqNum = pack('N', $seqNum);
        $macBlock = substr(hash_hmac('md5', $seqNum . $message, $key, true), 0, 10);
        /** a 2-byte message type number in network byte order with value 1 */
        $macBlock .= "\x00\x01";
        $macBlock .= $seqNum;

        return $macBlock;
    }

    /**
     * The keys for integrity protecting messages from client to server / server to client:
     *
     *   Kic = MD5({H(A1), "Digest session key to client-to-server signing key magic constant"})
     *   Kis = MD5({H(A1), "Digest session key to server-to-client signing key magic constant"})
     *
     */
    protected function generateKeyKi(string $a1, string $mc): string
    {
        return hash('md5', $a1 . $mc, true);
    }

    /**
     * The key for encrypting messages from client to server / server to client:
     *
     *   Kcc = MD5({H(A1)[0..n], "Digest H(A1) to client-to-server sealing key magic constant"})
     *   Kcs = MD5({H(A1)[0..n], "Digest H(A1) to server-to-client sealing key magic constant"})
     *
     * Where the key size is determined by "n" above.
     */
    protected function generateKeyKc(string $a1, string $cipher, string $mc): string
    {
        return hash(
            'md5',
            substr($a1, 0, self::CIPHERS[$cipher]['kcn']) . $mc,
            true
        );
    }

    protected function generateKeyAndIV(string $cipher, string $kc): array
    {
        # No IV and all of the kc for the key with RC4 types
        if ($cipher === 'rc4' || $cipher === 'rc4-40' || $cipher === 'rc4-56') {
            return ['', $kc];
        }

        $iv = substr($kc, 8, 8);
        if ($cipher === 'des') {
            $key = $this->expandDesKey(substr($kc, 0, 7));
        } else {
            $key1 = substr($kc, 0, 7);
            $key2 = substr($kc, 7, 7);

            $key = '';
            foreach ([$key1, $key2, $key1] as $desKey) {
                $key .= $this->expandDesKey($desKey);
            }
        }

        return [$iv, $key];
    }

    /**
     * We need to manually expand the 7-byte DES keys to 8-bytes. This shifts the first 7 bytes into the high seven bits.
     * This also ignores parity, as it should not be strictly necessary and just adds additional complexity here.
     */
    protected function expandDesKey(string $key): string
    {
        $bytes = [];

        for ($i = 0; $i < 7; $i++) {
            $bytes[$i] = ord($key[$i]);
        }

        return
            chr($bytes[0] & 0xfe) .
            chr(($bytes[0] << 7) | ($bytes[1] >> 1)) .
            chr(($bytes[1] << 6) | ($bytes[2] >> 2)) .
            chr(($bytes[2] << 5) | ($bytes[3] >> 3)) .
            chr(($bytes[3] << 4) | ($bytes[4] >> 4)) .
            chr(($bytes[4] << 3) | ($bytes[5] >> 5)) .
            chr(($bytes[5] << 2) | ($bytes[6] >> 6)) .
            chr($bytes[6] << 1);
    }

    /**
     * @throws SaslException
     */
    protected function validateBufferLength(string $data, SaslContext $context): void
    {
        $maxbuf = $context->has('maxbuf') ? (int) $context->get('maxbuf') : self::MAXBUF;
        if (strlen($data) > $maxbuf) {
            throw new SaslException(sprintf(
                'The wrapped buffer exceeds the maxbuf length of %s',
                $maxbuf
            ));
        }
    }
}

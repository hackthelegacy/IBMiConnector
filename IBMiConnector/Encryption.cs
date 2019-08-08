//-----------------------------------------------------------------------
// <copyright file="Encryption.cs" company="Bart Kulach">
// Copyright (C) 2018-2019 Bart Kulach
// This file, Encryption.cs, is part of the IBMiConnector package.
//
// "IBMiConnector" is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// "IBMiConnector" is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.If not, see http://www.gnu.org/licenses/
// </copyright>
//-----------------------------------------------------------------------

namespace IBMiConnector
{
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Class Encryption delivers utilities to perform password encryption for IBM i Systems.
    /// </summary>
    internal static class Encryption
    {
        /// <summary>Encrypts password using IBM's flavor of SHA1 algorithm</summary>
        /// <param name="userName">User name in ASCII</param>
        /// <param name="password">Password in ASCII</param>
        /// <param name="serverSeed">Server's seed</param>
        /// <param name="clientSeed">Client's seed</param>
        /// <returns>Encrypted password as EBCDIC byte stream</returns>
        public static byte[] EncryptPasswordSHA1(string userName, string password, ulong serverSeed, ulong clientSeed)
        {
            SHA1 sha = new SHA1CryptoServiceProvider();
            byte[] token = sha.ComputeHash(Encoding.BigEndianUnicode.GetBytes(userName.ToUpper().PadRight(10) + password));
            byte[] serverSeedBytes = Converters.UInt64ToBigEndian(serverSeed);
            byte[] clientSeedBytes = Converters.UInt64ToBigEndian(clientSeed);
            byte[] userNameUnicodeBytes = Encoding.BigEndianUnicode.GetBytes(userName.ToUpper().PadRight(10));
            byte[] sequenceBytes = Converters.UInt64ToBigEndian(1);

            sha = new SHA1CryptoServiceProvider();
            sha.TransformBlock(token, 0, token.Length, token, 0);
            sha.TransformBlock(serverSeedBytes, 0, serverSeedBytes.Length, serverSeedBytes, 0);
            sha.TransformBlock(clientSeedBytes, 0, clientSeedBytes.Length, clientSeedBytes, 0);
            sha.TransformBlock(userNameUnicodeBytes, 0, userNameUnicodeBytes.Length, userNameUnicodeBytes, 0);
            sha.TransformFinalBlock(sequenceBytes, 0, sequenceBytes.Length);
            return sha.Hash;
        }

        /// <summary>Encrypts password using IBM's flavor of DES algorithm as defined in RFC2877</summary>
        /// <param name="userName">User name in ASCII</param>
        /// <param name="password">Password in ASCII</param>
        /// <param name="serverSeed">Server's seed</param>
        /// <param name="clientSeed">Client's seed</param>
        /// <returns>Encrypted password as EBCDIC byte stream</returns>
        public static byte[] EncryptPasswordDES(string userName, string password, ulong serverSeed, ulong clientSeed)
        {
            byte[] passwordToken = new byte[8];
            if (password.Length > 8)
            {
                byte[] passwordTokenA = GenerateToken(userName, password.Substring(0, 8));
                byte[] passwordTokenB = GenerateToken(userName, password.Substring(8));
                passwordToken = Converters.UInt64ToBigEndian(Converters.BigEndianToUInt64(passwordTokenA) ^ Converters.BigEndianToUInt64(passwordTokenB));
            }
            else
                passwordToken = GenerateToken(userName, password);

            byte[] usernameEBCDIC_A;
            byte[] usernameEBCDIC_B;

            if (userName.Length <= 8)
            {
                usernameEBCDIC_A = Converters.AsciiToEbcdic(userName.ToUpper().PadRight(8));
                usernameEBCDIC_B = Converters.UInt64ToBigEndian(0x4040404040404040);
            }
            else
            {
                usernameEBCDIC_A = Converters.AsciiToEbcdic(userName.Substring(0, 8).ToUpper().PadRight(8));
                usernameEBCDIC_B = Converters.AsciiToEbcdic(userName.Substring(8).ToUpper().PadRight(8));
            }

            byte[] firstEncryptionRound = EncryptDES(Converters.UInt64ToBigEndian(serverSeed + 1), passwordToken);
            byte[] secondEncryptionRound = EncryptDES(Converters.UInt64ToBigEndian(Converters.BigEndianToUInt64(firstEncryptionRound) ^ clientSeed), passwordToken);
            byte[] thirdEncryptionRound = EncryptDES(Converters.UInt64ToBigEndian(Converters.BigEndianToUInt64(usernameEBCDIC_A) ^ (serverSeed + 1) ^ Converters.BigEndianToUInt64(secondEncryptionRound)), passwordToken);
            byte[] fourthEncryptionRound = EncryptDES(Converters.UInt64ToBigEndian(Converters.BigEndianToUInt64(usernameEBCDIC_B) ^ (serverSeed + 1) ^ Converters.BigEndianToUInt64(thirdEncryptionRound)), passwordToken);
            return EncryptDES(Converters.UInt64ToBigEndian(Converters.BigEndianToUInt64(fourthEncryptionRound) ^ 0x0000000000000001), passwordToken);
        }

        /// <summary>Creates an intermediary password token using DES algorithm</summary>
        /// <param name="userName">User name in ASCII</param>
        /// <param name="password">Password in ASCII</param>
        /// <returns>Encrypted password token as EBCDIC byte stream</returns>
        private static byte[] GenerateToken(string userName, string password)
        {
            if (password.Length > 8)
                throw new System.InvalidOperationException("Wrong method invocation: password cannot be longer than 8");

            if (userName.Length > 10)
                throw new System.InvalidOperationException("Wrong method invocation: user name cannot be longer than 10");

            byte[] passwordEBCDIC = Converters.AsciiToEbcdic(password.ToUpper().PadRight(8));

            byte[] encryptionKey = Converters.UInt64ToBigEndian((Converters.BigEndianToUInt64(passwordEBCDIC) ^ 0x5555555555555555) << 1);

            byte[] usernameEBCDIC = PrepareUserNameDES(userName);

            return EncryptDES(usernameEBCDIC, encryptionKey);
        }

        /// <summary>Performs DES encryption using the chosen cipher mode</summary>
        /// <param name="data">Data to be encrypted</param>
        /// <param name="key">Encryption key</param>
        /// <returns>Encrypted byte stream</returns>
        private static byte[] EncryptDES(byte[] data, byte[] key)
        {
            return EncryptDES(data, key, CipherMode.ECB, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
        }

        /// <summary>Performs DES encryption using the chosen cipher mode</summary>
        /// <param name="data">Data to be encrypted</param>
        /// <param name="key">Encryption key</param>
        /// <param name="cipherMode">DES cipher mode (e.g. ECB, CBC etc.)</param>
        /// <param name="bufferIV">IV buffer initial value</param>
        /// <returns>Encrypted byte stream</returns>
        private static byte[] EncryptDES(byte[] data, byte[] key, CipherMode cipherMode, byte[] bufferIV)
        {
            DESCryptoServiceProvider desProvider = new DESCryptoServiceProvider
            {
                Mode = cipherMode,
                Padding = PaddingMode.None,
                IV = bufferIV,
                BlockSize = 64,
                Key = key
            };

            MemoryStream stream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(stream, desProvider.CreateEncryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(data, 0, 8);
            cryptoStream.FlushFinalBlock();

            return stream.ToArray();
        }

        /// <summary>Prepares user name for usage DES algorithm according to RFC2877 5.1. step 4</summary>
        /// <param name="userName">User name in ASCII</param>
        /// <returns>User name as EBCDIC byte stream</returns>
        private static byte[] PrepareUserNameDES(string userName)
        {
            byte[] usernameEBCDIC = new byte[8];

            if (userName.Length <= 8)
                usernameEBCDIC = Converters.AsciiToEbcdic(userName.ToUpper().PadRight(8));
            else
            {
                usernameEBCDIC = Converters.AsciiToEbcdic(userName.ToUpper().Substring(0, 8));
                byte usernameEBCDIC_9 = Converters.AsciiToEbcdic(userName.ToUpper().PadRight(10).Substring(8, 1))[0];
                byte usernameEBCDIC_10 = Converters.AsciiToEbcdic(userName.ToUpper().PadRight(10).Substring(9, 1))[0];
                usernameEBCDIC[0] ^= (byte)(usernameEBCDIC_9 & 0xC0);
                usernameEBCDIC[1] ^= (byte)(((usernameEBCDIC_9 & 0x30) << 2) & 0xFF);
                usernameEBCDIC[2] ^= (byte)(((usernameEBCDIC_9 & 0x0C) << 4) & 0xFF);
                usernameEBCDIC[3] ^= (byte)((usernameEBCDIC_9 << 6) & 0xFF);
                usernameEBCDIC[4] ^= (byte)(usernameEBCDIC_10 & 0xC0);
                usernameEBCDIC[5] ^= (byte)(((usernameEBCDIC_10 & 0x30) << 2) & 0xFF);
                usernameEBCDIC[6] ^= (byte)(((usernameEBCDIC_10 & 0x0C) << 4) & 0xFF);
                usernameEBCDIC[7] ^= (byte)((usernameEBCDIC_10 << 6) & 0xFF);
            }

            return usernameEBCDIC;
        }
    }
}
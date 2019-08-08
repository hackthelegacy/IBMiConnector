//-----------------------------------------------------------------------
// <copyright file="Converters.cs" company="Bart Kulach">
// Copyright (C) 2018-2019 Bart Kulach
// This file, Converters.cs, is part of the IBMiConnector package.
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
    using System;
    using System.Diagnostics;
    using System.Text;

    /// <summary>
    /// Class Converters delivers utilities to convert between IBM and non-IBM data formats.
    /// </summary>
    public static class Converters
    {
        /// <summary>Converts a long value from big endian to small endian</summary>
        /// <param name="value">Value to be converted</param>
        /// <returns>Converted value</returns>
        public static byte[] UInt64ToBigEndian(ulong value)
        {
            byte[] returnValue = new byte[8];
            for (int i = 0; i < 8; i++)
                returnValue[i] = (byte)((value >> (64 - ((i + 1) * 8))) & 0xFF);

            return returnValue;
        }

        /// <summary>Converts an int value from big endian to small endian</summary>
        /// <param name="value">Value to be converted</param>
        /// <returns>Converted value</returns>
        public static byte[] UInt32ToBigEndian(uint value)
        {
            byte[] returnValue = new byte[4];
            for (int i = 0; i < 4; i++)
                returnValue[i] = (byte)((value >> (32 - ((i + 1) * 8))) & 0xFF);

            return returnValue;
        }

        /// <summary>Converts a short value from big endian to small endian</summary>
        /// <param name="value">Value to be converted</param>
        /// <returns>Converted value</returns>
        public static byte[] UInt16ToBigEndian(uint value)
        {
            byte[] returnValue = new byte[2];
            for (int i = 0; i < 2; i++)
                returnValue[i] = (byte)((value >> (16 - ((i + 1) * 8))) & 0xFF);

            return returnValue;
        }

        /// <summary>Converts a byte value from big endian to small endian</summary>
        /// <param name="value">Value to be converted</param>
        /// <returns>Converted value</returns>
        public static byte[] UInt8ToBigEndian(byte value)
        {
            byte[] returnValue = new byte[1];
            returnValue[0] = value;

            return returnValue;
        }

        /// <summary>Converts a long value from big endian to small endian</summary>
        /// <param name="value">Byte array (big endian) with the value to be converted</param>
        /// <param name="offset">Offset to the value to be converted</param>
        /// <param name="length">Length of the variable (right justified)</param>
        /// <returns>Converted value</returns>
        public static ulong BigEndianToUInt64(byte[] value, uint offset = 0, uint length = 8)
        {
            if (value.Length - offset < length)
                return 0;

            ulong returnValue = 0;

            for (int i = 8 - (int)length; i < 8; i++)
                returnValue += (ulong)value[offset + i + (int)length - 8] << (64 - ((i + 1) * 8));
            return returnValue;
        }

        /// <summary>Converts an int value from big endian to small endian </summary>
        /// <param name="value">Byte array (big endian) with the value to be converted</param>
        /// <param name="offset">Offset to the value to be converted</param>
        /// <param name="length">Length of the variable (right justified)</param>
        /// <returns>Converted value</returns>
        public static uint BigEndianToUInt32(byte[] value, uint offset = 0, uint length = 4)
        {
            if (value.Length - offset < length)
                return 0;

            uint returnValue = 0;

            for (int i = 4 - (int)length; i < 4; i++)
                returnValue += (uint)value[offset + i + (int)length - 4] << (32 - ((i + 1) * 8));
            return returnValue;
        }

        /// <summary>Converts a short value from big endian to small endian </summary>
        /// <param name="value">Byte array (big endian) with the value to be converted</param>
        /// <param name="offset">Offset to the value to be converted</param>
        /// <returns>Converted value</returns>
        public static ushort BigEndianToUInt16(byte[] value, uint offset = 0)
        {
            if (value.Length - offset < 2)
                return 0;

            ushort returnValue = 0;

            for (int i = 0; i < 2; i++)
                returnValue += (ushort)(value[offset + i] << (16 - ((i + 1) * 8)));
            return returnValue;
        }

        /// <summary>Converts a short value from big endian to small endian </summary>
        /// <param name="value">Byte array (big endian) with the value to be converted</param>
        /// <param name="offset">Offset to the value to be converted</param>
        /// <returns>Converted value</returns>
        public static byte BigEndianToUInt8(byte[] value, uint offset = 0)
        {
            if (offset >= value.Length)
                return 0;

            return value[offset];
        }

        /// <summary>Converts a big endian byte array to a hex string</summary>
        /// <param name="value">Byte array (big endian) with the value to be converted</param>
        /// <param name="offset">Offset to the value to be converted</param>
        /// <param name="length">Length of the text to be converted (if 0, all bytes from offset will be converted)</param>
        /// <returns>Converted value</returns>
        public static string BigEndianToHexString(byte[] value, uint offset = 0, uint length = 0)
        {
            string hexString = string.Empty;

            if (offset >= value.Length)
                return string.Empty;

            uint count = (length == 0) ? (uint)value.Length - offset : length;

            for (int i = 0; i < count; i++)
                hexString += value[offset + i].ToString("X2");
            return hexString;
        }

        /// <summary>Converts an EBCDIC byte stream to ASCII byte stream</summary>
        /// <param name="value">Byte array with the EBCDIC byte stream to be converted</param>
        /// <param name="offset">Offset to the text to be converted</param>
        /// <param name="length">Length of the text to be converted (if 0, all text)</param>
        /// <param name="ccsid">IBM codepage of the value to be converted</param>
        /// <returns>Converted value</returns>
        public static byte[] EbcdicToAscii(byte[] value, uint offset = 0, uint length = 0, int ccsid = 37)
        {
            if (value.Length - offset < length)
                return null;

            // Create encoder and decoder.      
            Encoding ascii = Encoding.ASCII;
            Encoding ebcdic = Encoding.GetEncoding(ccsid);

            uint count = (length == 0) ? (uint)value.Length - offset : length;

            // Return ASCII Data 
            try
            {
                return Encoding.Convert(ebcdic, ascii, value, (int)offset, (int)count);
            }
            catch (Exception e)
            {
                Debug.WriteLine("Exception occured:" + e.Message);
                return null;
            }            
        }

        /// <summary>Converts an EBCDIC byte stream to ASCII byte stream</summary>
        /// <param name="value">Byte array with the EBCDIC byte stream to be converted</param>
        /// <param name="offset">Offset to the text to be converted</param>
        /// <param name="length">Length of the text to be converted (if -1, all text)</param>
        /// <param name="ccsid">IBM codepage of the value to be converted</param>
        /// <returns>Converted value</returns>
        public static string EbcdicToAsciiString(byte[] value, uint offset = 0, uint length = 0, int ccsid = 37)
        {
            if (value.Length - offset < length)
                return string.Empty;

            try
            {
                return Encoding.ASCII.GetString(EbcdicToAscii(value, offset, length, ccsid));
            }
            catch (Exception e)
            {
                Debug.WriteLine("Exception occured:" + e.Message);
                return null;
            }
        }

        /// <summary>Converts an ASCII byte stream to EBCDIC byte stream</summary>
        /// <param name="value">Byte array with the ASCII byte stream to be converted</param>
        /// <param name="offset">Offset to the text to be converted</param>
        /// <param name="length">Length of the text to be converted (if -1, all text)</param>
        /// <param name="ccsid">IBM codepage of the return value</param>
        /// <returns>Converted value</returns>
        public static byte[] AsciiToEbcdic(byte[] value, uint offset = 0, uint length = 0, int ccsid = 37)
        {
            if (value.Length - offset < length)
                return null;

            // Create encoder and decoder.      
            Encoding ascii = Encoding.ASCII;
            Encoding ebcdic = Encoding.GetEncoding(ccsid);

            uint count = (length == 0) ? (uint)value.Length - offset : length;

            // Return EBCDIC Data 
            return Encoding.Convert(ascii, ebcdic, value, (int)offset, (int)count);
        }

        /// <summary>Converts an ASCII string to EBCDIC byte stream</summary>
        /// <param name="value">ASCII string to be converted</param>
        /// <param name="ccsid">IBM codepage of the return value</param>
        /// <returns>Converted value</returns>
        public static byte[] AsciiToEbcdic(string value, int ccsid = 37)
        {
            return AsciiToEbcdic(Encoding.ASCII.GetBytes(value), 0, 0, ccsid);
        }

        /// <summary>Converts an unformatted timestamp (DTS) to DateTime.
        /// DTS specify microseconds elapsed since August 23, 1928 12:03:06.314752.</summary>
        /// <param name="value">Byte array with the byte stream to be converted (length of 8 bytes)</param>
        /// <param name="offset">Offset to the text to be converted</param>
        /// <returns>Converted value</returns>
        public static DateTime DTSTimeStampToDateTime(byte[] value, uint offset = 0)
        {
            /* The Standard Time Format [*DTS] is defined as a 64-bit (8-byte) unsigned binary value as follows:
            *
            * Offset
            * Dec  Hex   Field Name             Data Type and Length
            * ___  ___   ____________________   ____________________
            * 0    0     Standard Time Format   UBin(8)
            * 0    0     Time                   Bits 0-51  (52 bits)
            * 0    0     Uniqueness bits        Bits 52-63 (12 bits)
            * 8    8     --- End ---
            *
            *
            * The time field is a binary number which can be interpreted as a time value in units of 1 microsecond. 
            * A binary 1 in bit 51 is equal to 1 microsecond.
            *
            * The "uniqueness bits" field may contain any combination of binary 1s and 0s. 
            * These bits do not provide additional granularity for a time value; 
            * they merely allow unique 64-bit values to be returned, such as when the value of the time-of-day (TOD) clock 
            * is materialized. When the uniqueness bits all contain binary 0s, then the 64-bit value returned is not unique. Unless explicitly stated otherwise, MI instructions which materialize the TOD clock return a unique 64-bit value.
            */

            if (offset + 8 >= value.Length)
                return default(DateTime);

            ulong timestampDTS = BigEndianToUInt64(value, offset);

            timestampDTS -= 0x8000000000000000;
            timestampDTS >>= 12;
            timestampDTS += 946684800000000;
            timestampDTS /= 1000;

            return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddMilliseconds(timestampDTS);
        }
    }
}

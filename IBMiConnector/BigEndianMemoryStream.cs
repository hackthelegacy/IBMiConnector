//-----------------------------------------------------------------------
// <copyright file="BigEndianMemoryStream.cs" company="Bart Kulach">
// Copyright (C) 2018-2019 Bart Kulach
// This file, BigEndianMemoryStream.cs, is part of the IBMiConnector package.
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
    using System.IO;

    /// <summary>
    /// Class BigEndianMemoryStream delivers an interface for big-endian conversion of data for socket connectivity.
    /// </summary>
    public class BigEndianMemoryStream : MemoryStream
    {
        /// <summary>Writes a long value to the stream</summary>
        /// <param name="value">Value to be written to the stream</param>
        public void WriteLong(ulong value)
        {
            byte[] longArray = new byte[8];
            longArray[0] = (byte)((value >> 56) & 0xFF);
            longArray[1] = (byte)((value >> 48) & 0xFF);
            longArray[2] = (byte)((value >> 40) & 0xFF);
            longArray[3] = (byte)((value >> 32) & 0xFF);
            longArray[4] = (byte)((value >> 24) & 0xFF);
            longArray[5] = (byte)((value >> 16) & 0xFF);
            longArray[6] = (byte)((value >> 8) & 0xFF);
            longArray[7] = (byte)(value & 0xFF);
            this.Write(longArray, 0, 8);
        }

        /// <summary>Writes an int value to the stream</summary>
        /// <param name="value">Value to be written to the stream</param>
        public void WriteInt(uint value)
        {   
            byte[] intArray = new byte[4];
            intArray[0] = (byte)((value >> 24) & 0xFF);
            intArray[1] = (byte)((value >> 16) & 0xFF);
            intArray[2] = (byte)((value >> 8) & 0xFF);
            intArray[3] = (byte)(value & 0xFF);
            this.Write(intArray, 0, 4);
        }

        /// <summary>Writes a short value to the stream</summary>
        /// <param name="value">Value to be written to the stream</param>
        public void WriteShort(ushort value)
        {
            byte[] shortArray = new byte[2];
            shortArray[0] = (byte)((value >> 8) & 0xFF);
            shortArray[1] = (byte)(value & 0xFF);
            this.Write(shortArray, 0, 2);
        }

        /// <summary>Reads a long value from the stream</summary>
        /// <returns>A long value</returns>
        public ulong ReadLong()
        {
            byte[] longArray = new byte[8];
            this.Read(longArray, 0, 8);
            return Converters.BigEndianToUInt64(longArray);
        }

        /// <summary>Reads an int value from the stream</summary>
        /// <returns>A int value</returns>
        public uint ReadInt()
        {
            byte[] intArray = new byte[4];
            this.Read(intArray, 0, 4);
            return Converters.BigEndianToUInt32(intArray);
        }

        /// <summary>Reads a short value from the stream</summary>
        /// <returns>A short value</returns>
        public ushort ReadShort()
        {
            byte[] shortArray = new byte[2];
            this.Read(shortArray, 0, 2);
            return Converters.BigEndianToUInt16(shortArray);
        }
    }
}
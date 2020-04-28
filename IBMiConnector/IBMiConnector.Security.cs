//-----------------------------------------------------------------------
// <copyright file="Security.cs" company="Bart Kulach">
// Copyright (C) 2018-2019 Bart Kulach
// This file, Security.cs, is part of the IBMiConnector package.
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

    /// <content>
    /// This file implements methods related to security.
    /// </content>
    public partial class IBMiConnector
    {
        //-----------------------------------------------------------------------
        // Class fields
        //-----------------------------------------------------------------------

        /// <summary>Constant for password hash type (first DES hash)</summary>
        public const ushort PASSWORD_HASH_FIRSTDES = 0;

        /// <summary>Constant for password hash type (second DES hash)</summary>
        public const ushort PASSWORD_HASH_SECONDDES = 1;

        /// <summary>Constant for password hash type (both DES hashes)</summary>
        public const ushort PASSWORD_HASH_DES = 7;

        /// <summary>Constant for password hash type (LM hash)</summary>
        public const ushort PASSWORD_HASH_LMHASH = 2;

        /// <summary>Constant for password hash type (SHA1 uppercase)</summary>
        public const ushort PASSWORD_HASH_HMACSHA1UC = 3;

        /// <summary>Constant for password hash type (SHA1 mixed case)</summary>
        public const ushort PASSWORD_HASH_HMACSHA1MC = 6;

        /// <summary>Constant for password hash type (unknown)</summary>
        public const ushort PASSWORD_HASH_UNKNOWNHASH = 4;

        /// <summary>Constant for password hash type (all hash data)</summary>
        public const ushort PASSWORD_HASH_ALLDATA = 5;

        //-----------------------------------------------------------------------
        // Class methods
        //-----------------------------------------------------------------------

        /// <summary>Returns password hash of the specified user, in specified format</summary>
        /// <param name="system">System to be connected to</param>
        /// <param name="userName">User name</param>
        /// <param name="hashType">Predefined password hash type (see documentation for details)</param>
        /// <returns>Password hash as a hex string</returns>
        public string GetEncryptedPassword(string userName, int hashType)
        {
            /*
             *  http://publib.boulder.ibm.com/infocenter/iseries/v5r4/index.jsp?topic=%2Fapis%2Fqsyrupwd.htm
             * 
             *  Required Parameter Group:
             *
             *   1   Receiver variable              Output   Char(*) - 2000B
             *   2   Length of receiver variable    Input    Binary(4) 
             *   3   Format                         Input    Char(8) - "UPWD0100"
             *   4   User profile name              Input    Char(10) - userName
             *   5   Error code                     I/O      Char(*)
             */

            ProgramCallParameters qsyrupwdCallParameters =
                new ProgramCallParameters(5)
                {
                    [0] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeOutput,
                        null,
                        2000),
                    [1] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.UInt32ToBigEndian(2000)),
                    [2] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.AsciiToEbcdic("UPWD0100")),
                    [3] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.AsciiToEbcdic(userName.ToUpper().PadRight(10))),
                    [4] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInputOutput,
                        null,
                        500)
                };
            CallMessages qsyrupwdCallMessages = new CallMessages();

            if (CallProgram("QSYRUPWD", "QSYS", ref qsyrupwdCallParameters, ref qsyrupwdCallMessages) != 0)
            {
                foreach (CallMessage outputMessage in qsyrupwdCallMessages)
                    Debug.WriteLine(outputMessage.MessageText);
                throw new System.InvalidOperationException("The method GetEncryptedPassword failed. Check debug information.");
            }


            switch (hashType)
            {
                case PASSWORD_HASH_ALLDATA: // All data
                    return Converters.BigEndianToHexString(qsyrupwdCallParameters[0].ParameterValue, 1, 269);
                case PASSWORD_HASH_UNKNOWNHASH: // Unknown (hash?) data
                    return Converters.BigEndianToHexString(qsyrupwdCallParameters[0].ParameterValue, 78, 192);
                case PASSWORD_HASH_HMACSHA1MC: // HMAC-SHA1 password (mixed case)
                    return Converters.BigEndianToHexString(qsyrupwdCallParameters[0].ParameterValue, 35, 20);
                case PASSWORD_HASH_HMACSHA1UC: // HMAC-SHA1 password (uppercase)
                    return Converters.BigEndianToHexString(qsyrupwdCallParameters[0].ParameterValue, 55, 20);
                case PASSWORD_HASH_LMHASH: // LM hash
                    return Converters.BigEndianToHexString(qsyrupwdCallParameters[0].ParameterValue, 17, 16);
                case PASSWORD_HASH_DES: // Composed DES hash (PW_TOKENa XOR PW_TOKENb):
                    return Converters.BigEndianToHexString(Converters.UInt64ToBigEndian(Converters.BigEndianToUInt64(qsyrupwdCallParameters[0].ParameterValue, 1, 8) ^ Converters.BigEndianToUInt64(qsyrupwdCallParameters[0].ParameterValue, 9, 8)));
                case PASSWORD_HASH_SECONDDES: // Second DES password token (PW_TOKENb)
                    return Converters.BigEndianToHexString(qsyrupwdCallParameters[0].ParameterValue, 9, 8);
                case PASSWORD_HASH_FIRSTDES: // First DES password (PW_TOKENa)
                default:
                    return Converters.BigEndianToHexString(qsyrupwdCallParameters[0].ParameterValue, 1, 8);
            }
        }

        /// <summary>Sets user's password to a specified value</summary>
        /// <param name="userName">User name</param>
        /// <param name="newPassword">New password to be set</param>
        /// <param name="currentPassword">User's current password (optional if user is *SECADM and has at least *USE authority to the profile)</param>
        public void ChangeUserPassword(string userName, string newPassword, string currentPassword = "*CURPWD")
        {
            /*
             *  https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_73/apis/QSYCHGPW.htm
             * 
             *  Required Parameter Group:
             *
             *   1   User ID		            Input    Char(10)
             *   2   Current password		    Input    Char(*)
             *   3   New password	            Input    Char(*)  
             *   4   Error code                     I/O      Char(*)
             */

            ProgramCallParameters qsychgpwCallParameters =
                new ProgramCallParameters(4)
                {
                    [0] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.AsciiToEbcdic(userName.ToUpper().PadRight(10))),
                    [1] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.AsciiToEbcdic(currentPassword)),
                    [2] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.AsciiToEbcdic(newPassword)),
                    [3] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInputOutput,
                        null,
                        500)
                };

            CallMessages qsychgpwCallMessages = new CallMessages();

            if (CallProgram("qsychgpw", "QSYS", ref qsychgpwCallParameters, ref qsychgpwCallMessages) != 0)
            {
                foreach (CallMessage outputMessage in qsychgpwCallMessages)
                    Debug.WriteLine(outputMessage.MessageText);
                throw new System.InvalidOperationException("The method ChangeUserPassword failed. Check debug information.");
            }
        }

        //-----------------------------------------------------------------------
        // Private methods
        //-----------------------------------------------------------------------
    }
}
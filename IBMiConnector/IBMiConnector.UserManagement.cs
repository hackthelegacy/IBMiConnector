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
    /// This file implements methods related to user management.
    /// </content>
    public partial class IBMiConnector
    {
        //-----------------------------------------------------------------------
        // Class fields
        //-----------------------------------------------------------------------

        /// <summary>
        /// Class UserProfile is used to store information related to the AS/400 user profile (based on USRI0300 format).
        /// </summary>
        public class UserProfile
        {
            //-----------------------------------------------------------------------
            // Class constructors
            //-----------------------------------------------------------------------

            /// <summary>Initializes a new instance of the <see cref="UserProfile"/> class.</summary>
            /// <param name="binaryData">Byte stream input</param>
            internal UserProfile(byte[] binaryData)
            {
                // Check whether the table is at least 712B long (V7R2 minimum)
                if (binaryData.Length < 712)
                    throw new System.InvalidOperationException("The received user data is too short for USRI0300 format.");

                // Check whether the returned bytes value makes sense
                if (Converters.BigEndianToUInt32(binaryData) > binaryData.Length)
                    throw new System.InvalidOperationException("The received data length is bigger than the buffer size. Exiting.");

                this.UserName = Converters.EbcdicToAsciiString(binaryData, 8, 10).ToUpper();
                this.AccountingCode = Converters.EbcdicToAsciiString(binaryData, 309, 15).ToUpper();
                //TODO: Implementation of other fields
            }

            //-----------------------------------------------------------------------
            // Properties
            //-----------------------------------------------------------------------

            /// <summary>Gets information about the user name</summary>
            public string UserName { get; }

            /// <summary>Gets information about the previous sign-on date and time</summary>
            public DateTime LastSignonDateTime { get; }

            /// <summary>Gets information about the number of invalid sign-on attempts</summary>
            public int FailedSignonCounter { get; }

            /// <summary>Gets information about the profile status</summary>
            public string Status { get; }

            /// <summary>Gets information about the last password change date</summary>
            public DateTime LastPasswordChangeDate { get; }

            /// <summary>Gets information about whether the user has password set to *NONE</summary>
            public bool PasswordIsNONE { get; }

            /// <summary>Gets information about the password expiration interval</summary>
            public uint PasswordExpirationInterval { get; }

            /// <summary>Gets information about the password expiration date</summary>
            public DateTime PasswordExpirationDate { get; }

            /// <summary>Gets information about the number of days until password expires</summary>
            public uint PasswordExpirationDays { get; }

            /// <summary>Gets information about whether the user's password is expired</summary>
            public bool PasswordIsExpired { get; }

            /// <summary>Gets information about the user's class name</summary>
            public string UserClass { get; }

            /// <summary>Gets information about the user's special authorities</summary>
            public string SpecialAuthorities { get; }

            /// <summary>Gets information about the user's group profile name</summary>
            public string GroupProfile { get; }

            /// <summary>Gets information about the user's profile object owner name</summary>
            public string Owner { get; }

            /// <summary>Gets information about the user's group authority</summary>
            public string GroupAuthority { get; }

            /// <summary>Gets information about the user's assistance level</summary>
            public string AssistanceLevel { get; }

            /// <summary>Gets information about the user's current library</summary>
            public string CurrentLibrary { get; }

            /// <summary>Gets information about the user's initial menu</summary>
            public string InitialMenu { get; }

            /// <summary>Gets information about the user's initial menu's library</summary>
            public string InitialMenuLibrary { get; }

            /// <summary>Gets information about the user's initial program</summary>
            public string InitialProgram { get; }

            /// <summary>Gets information about the user's initial program's library</summary>
            public string InitialProgramLibrary { get; }

            /// <summary>Gets information about the user's limited capabilities setting</summary>
            public string LimitCapabilities { get; }

            /// <summary>Gets information about the user's text description</summary>
            public string TextDescription { get; }

            /// <summary>Gets information about the user's display sign-on information setting</summary>
            public string DisplaySignonInformation { get; }

            /// <summary>Gets information about the user's limit device sessions setting</summary>
            public string LimitDeviceSessions { get; }

            /// <summary>Gets information about the user's keyboard buffering setting</summary>
            public string KeyboardBuffering { get; }

            /// <summary>Gets information about the user's maximum allowed storage setting</summary>
            public uint MaximumAllowedStorage { get; }

            /// <summary>Gets information about the user's current used storage</summary>
            public uint StorageUsed { get; }

            /// <summary>Gets information about the user's scheduling priority setting</summary>
            public bool HighestSchedulingPriority { get; }

            /// <summary>Gets information about the user's job description name</summary>
            public string JobDescription { get; }

            /// <summary>Gets information about the user's job description's library</summary>
            public string JobDescriptionLibrary { get; }

            /// <summary>Gets information about the user's accounting code</summary>
            public string AccountingCode { get; }

            /// <summary>Gets information about the user's message queue name</summary>
            public string MessageQueue { get; }

            /// <summary>Gets information about the user's message queue's library</summary>
            public string MessageQueueLibrary { get; }

            /// <summary>Gets information about the user's message queue's delivery method</summary>
            public string MessageQueueDeliveryMethod { get; }

            /// <summary>Gets information about the user's message queue's delivery method</summary>
            public uint MessageQueueSeverity { get; }

            /// <summary>Gets information about the user's output queue name</summary>
            public string OutputQueue { get; }

            /// <summary>Gets information about the user's output queue's library</summary>
            public string OutputQueueLibrary { get; }

            /// <summary>Gets information about the user's print device</summary>
            public string PrintDevice { get; }

            /// <summary>Gets information about the user's special environment setting</summary>
            public string SpecialEnvironment { get; }

            /// <summary>Gets information about the user's attention key handling program name</summary>
            public string AttentionKeyProgram { get; }

            /// <summary>Gets information about the user's attention key handling program's library</summary>
            public string AttentionKeyProgramLibrary { get; }

            /// <summary>Gets information about the user's language ID setting</summary>
            public string LanguageID { get; }

            /// <summary>Gets information about the user's country or region ID setting</summary>
            public string CountryRegionID { get; }

            /// <summary>Gets information about the user's character code set ID setting</summary>
            public uint CharacterCodeID { get; }

            /// <summary>Gets information about the user options setting</summary>
            public string UserOptions { get; }

            /// <summary>Gets information about the user's sort sequence table name</summary>
            public string SortSequenceTable { get; }

            /// <summary>Gets information about the user's sort sequence table library</summary>
            public string SortSequenceTableLibrary { get; }

            /// <summary>Gets information about the user's object auditing value setting</summary>
            public string ObjectAuditingValue { get; }

            /// <summary>Gets information about the user's action audit level setting</summary>
            public string UserActionAuditLevel { get; }

            /// <summary>Gets information about the user's group authority type</summary>
            public string GroupAuthorityType { get; }

            /// <summary>Gets information about the user ID value</summary>
            public uint UserID { get; }

            /// <summary>Gets information about the group ID value</summary>
            public uint GroupID { get; }

            /// <summary>Gets information about the user's local job attributes setting</summary>
            public string LocaleJobAttributes { get; }

            /// <summary>Gets information about the user's group member indicator</summary>
            public bool GroupMemberIndicator { get; }

            /// <summary>Gets information about the user's digital certificate indicator</summary>
            public bool DigitalCertificateIndicator { get; }

            /// <summary>Gets information about the user's character identifier control setting</summary>
            public string CharacterIdentifierControl { get; }

            /// <summary>Gets information about the user's local password management</summary>
            public bool LocalPasswordManagement { get; }

            /// <summary>Gets information about the user's block password change setting</summary>
            public string BlockPasswordChange { get; }

            /// <summary>Gets information about the user's user entitlement required setting</summary>
            public bool UserEntitlementRequired { get; }

            /// <summary>Gets information about the user's expiration interval setting</summary>
            public int UserExpirationInterval { get; }

            /// <summary>Gets information about the user's expiration date</summary>
            public DateTime UserExpirationDate { get; }

            /// <summary>Gets information about the user's expiration action setting</summary>
            public String UserExpirationAction { get; }

            /// <summary>Gets information about the user's maximum allowed storage setting</summary>
            public ulong MaximumAllowedStorageLong { get; }

            /// <summary>Gets information about the user's current used storage</summary>
            public ulong StorageUsedLong { get; }

            //-----------------------------------------------------------------------
            // Class methods
            //-----------------------------------------------------------------------
        }

        //-----------------------------------------------------------------------
        // Class methods
        //-----------------------------------------------------------------------

        public string[] GetUsersList()
        {
            /*
             *  https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_72/apis/qgyolaus.htm
             * 
             *  Required Parameter Group:
             *
             *   1   Receiver variable              Output   Char(*) - 120000B
             *   2   Length of receiver variable    Input    Binary(4) - 120000
             *   3   List information               Output   Char(80)  
             *   4   Number of records to return    Input    Binary(4) - "9999"
             *   5   Format name                    Input    Char(8) - "AUTU0100"
             *   6   Selection criteria             Input    Char(10) - "*ALL"
             *   7   Group profile name             Input    Char(10) - "*NONE"
             *   8   Error code                     I/O      Char(*)
             */

            ProgramCallParameters qgyolausCallParameters =
                new ProgramCallParameters(8)
                {
                    [0] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeOutput,
                        null,
                        120000),
                    [1] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.UInt32ToBigEndian(120000)),
                    [2] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeOutput,
                        null,
                        80),
                    [3] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.UInt32ToBigEndian(9999)),
                    [4] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.AsciiToEbcdic("AUTU0100")),
                    [5] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.AsciiToEbcdic("*ALL      ")),
                    [6] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.AsciiToEbcdic("*NONE     ")),
                    [7] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInputOutput,
                        null,
                        500)
                };

            CallMessages qgyolausCallMessages = new CallMessages();

            if (CallProgram("QGYOLAUS", "QSYS", ref qgyolausCallParameters, ref qgyolausCallMessages) != 0)
            {
                foreach (CallMessage outputMessage in qgyolausCallMessages)
                    Debug.WriteLine(outputMessage.MessageText);
                throw new System.InvalidOperationException("The method GetUserList failed. Check debug information.");
            }

            uint numEntries = Converters.BigEndianToUInt32(qgyolausCallParameters[2].ParameterValue, 0, 4);
            if (numEntries <= 0)
                return null;

            string[] userList = new string[numEntries];
            for (int i = 0; i < numEntries; i++)
            {
                userList[i] = Converters.EbcdicToAsciiString(qgyolausCallParameters[0].ParameterValue, (uint)i * 12, 10);
            }
            return userList;
        }

        public UserProfile GetUserInfo(string userName)
        {
            /*
             *  https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_73/apis/qsyrusri.htm
             * 
             *  Required Parameter Group:
             *
             *   1   Receiver variable              Output   Char(*) - 120000B
             *   2   Length of receiver variable    Input    Binary(4) - 120000
             *   3   Format name                    Input    Char(8) - "USRI0300"
             *   4   User profile name              Input    Char(10) - userName
             *   5   Error code                     I/O      Char(*)
             */

            ProgramCallParameters qsyrusriCallParameters =
                new ProgramCallParameters(5)
                {
                    [0] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeOutput,
                        null,
                        120000),
                    [1] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.UInt32ToBigEndian(120000)),
                    [2] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.AsciiToEbcdic("USRI0300")),
                    [3] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInput,
                        Converters.AsciiToEbcdic(userName.ToUpper().PadRight(10))),
                    [4] = new ProgramCallParameter(
                        ProgramCallParameter.ParameterTypeInputOutput,
                        null,
                        500)
                };

            CallMessages qsyrusriCallMessages = new CallMessages();

            if (CallProgram("qsyrusri", "QSYS", ref qsyrusriCallParameters, ref qsyrusriCallMessages) != 0)
            {
                foreach (CallMessage outputMessage in qsyrusriCallMessages)
                    Debug.WriteLine(outputMessage.MessageText);
                throw new System.InvalidOperationException("The method GetUserInfo failed. Check debug information.");
            }

            return new UserProfile(qsyrusriCallParameters[0].ParameterValue);
        }

        //-----------------------------------------------------------------------
        // Private methods
        //-----------------------------------------------------------------------
    }
}
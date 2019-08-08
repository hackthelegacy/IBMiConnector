//-----------------------------------------------------------------------
// <copyright file="IBMiConnector.ProgramCalls.cs" company="Bart Kulach">
// Copyright (C) 2010-2018 Bart Kulach
// This file, IBMiConnector.Connectivity.cs, is part of the IBMiConnector package.
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
    using System.Collections;
    using System.Diagnostics;
    using System.Text;

    /// <content>
    /// This file implements methods related to connectivity.
    /// </content>
    public partial class IBMiConnector
    {
        //-----------------------------------------------------------------------
        // Class fields
        //-----------------------------------------------------------------------

        //-----------------------------------------------------------------------
        // Class methods
        //-----------------------------------------------------------------------

        /// <summary>Performs a program call.</summary>
        /// <param name="programName">Name of the program</param>
        /// <param name="programLibrary">Library where the program is located</param>
        /// <param name="programCallParameters">Program's parameters (by reference)</param>
        /// <param name="programCallMessages">Output variable for program call's messages</param>
        /// <returns>Program call return code and output data (in the parameters variable)</returns>
        public int CallProgram(string programName, string programLibrary, ref ProgramCallParameters programCallParameters, ref CallMessages programCallMessages)
        {
            // Establish command channel
            if (this.socketConnectorRemoteCommand == null)
                throw new System.InvalidOperationException("Operation failed, connection not established.");

            if (programName.Length > 10 || programLibrary.Length > 10)
                throw new System.InvalidOperationException("Wrong method invocation: program name / library name cannot be longer than 10 characters.");

            using (BigEndianMemoryStream outputStream = new BigEndianMemoryStream())
            {
                outputStream.WriteShort(0); // Header ID.
                outputStream.WriteShort(ServerIDRemoteCommand); // Server ID.
                outputStream.WriteInt(0); // CS instance.
                outputStream.WriteInt(0); // Correlation ID.
                outputStream.WriteShort(23); // Template length.
                outputStream.WriteShort(0x1003); // ReqRep ID.
                outputStream.Write(Converters.AsciiToEbcdic(programName.ToUpper().PadRight(10)), 0, 10);
                outputStream.Write(Converters.AsciiToEbcdic(programLibrary.ToUpper().PadRight(10)), 0, 10);

                byte messageOption;
                if (this.serverDatastreamLevel < 7)
                    messageOption = 0;
                else if (this.serverDatastreamLevel < 10)
                    messageOption = 2;
                else
                    messageOption = 4;

                outputStream.WriteByte(messageOption);
                outputStream.WriteShort((ushort)programCallParameters.Length);
                foreach (ProgramCallParameter programCallParameter in programCallParameters)
                {
                    outputStream.WriteInt((uint)(12 + (programCallParameter.ParameterValue?.Length ?? 0))); // Parameter LL
                    outputStream.WriteShort(0x1103); // Parameter CP
                    outputStream.WriteInt((uint)programCallParameter.ParameterMaxLength);
                    if (programCallParameter.ParameterType == ProgramCallParameter.ParameterTypeNull
                                                              && this.serverDatastreamLevel < 6)
                        outputStream.WriteShort(1); // NULL parameters not allowed in older data stream versions
                    else
                    {
                        outputStream.WriteShort(programCallParameter.ParameterType);
                        if (programCallParameter.ParameterValue != null)
                            outputStream.Write(programCallParameter.ParameterValue, 0, programCallParameter.ParameterValue.Length);
                    }
                }

                this.socketConnectorRemoteCommand.Write(outputStream.ToArray());
            }

            /*
             *  The response comes  in the following format:
             * 
             *  Offset (byte)       Information         Length (byte)
             *  -----------------------------------------------------------
             *  Fixed header
             *  -----------------------------------------------------------
             *  0                   Response length     4
             *  4                   (Reserved)          16
             *  20                  Result code         2
             *  22                  Number of messages  2
             *  
             *  -----------------------------------------------------------
             *  Dynamic fields (Offset is dynamic) - for Output and Input/Output
             *  -----------------------------------------------------------
             *  0                   Output length       4
             *  4                   Output code         2
             *  6                   Output max length   4
             *  10                  Output type         2
             *  12                  Field data          (Output length - 12)
             *
             *  -----------------------------------------------------------
             *  Dynamic fields (Offset is dynamic) - for Messages
             *  -----------------------------------------------------------
             *  0                   Message length      4
             *  4                   Message code        2
             *  6                   Message data        (Message length - 6)
             */

            // Retrieve server response
            byte[] response = this.socketConnectorRemoteCommand.Read();
            if (response == null)
                throw new System.InvalidOperationException("Program call failed. Bad response length.");

            uint responseLength = Converters.BigEndianToUInt32(response, 0);
            if (responseLength < 20)
                throw new System.InvalidOperationException("Program call failed. Bad response length.");

            // Read fixed header
            ushort resultCode = Converters.BigEndianToUInt16(response, 20);
            ushort returnedMessagesCount = Converters.BigEndianToUInt16(response, 22);
            if (resultCode != 0)
            {
                Debug.WriteLine("Program call failed, return code is 0x" + resultCode.ToString("X8"));

                if (programCallMessages != null && returnedMessagesCount > 0)
                {
                    byte[] outputMessages = new byte[responseLength - 24];
                    Array.Copy(response, 24, outputMessages, 0, outputMessages.Length);
                    programCallMessages.FromByteStream(returnedMessagesCount, outputMessages);
                }

                return (int)resultCode;
            }

            int readOffset = 24;
            foreach (ProgramCallParameter programCallParameter in programCallParameters)
            {
                if (readOffset > response.Length)
                    break;

                if (programCallParameter.ParameterType == ProgramCallParameter.ParameterTypeOutput
                    || programCallParameter.ParameterType == ProgramCallParameter.ParameterTypeInputOutput)
                {
                    uint dynamicFieldLength = Converters.BigEndianToUInt32(response, (uint)readOffset);
                    if (dynamicFieldLength == 0x40404040 || dynamicFieldLength == 0x00000000)
                        break;
                    ushort dynamicFieldCode = Converters.BigEndianToUInt16(response, (uint)readOffset + 4);
                    uint dynamicFieldOutputLength = Converters.BigEndianToUInt32(response, (uint)readOffset + 6);
                    ushort dynamicFieldType = Converters.BigEndianToUInt16(response, (uint)readOffset + 10);
                    byte[] dynamicFieldData = new byte[dynamicFieldLength - 12];
                    Array.Copy(response, readOffset + 12, dynamicFieldData, 0, dynamicFieldData.Length);
                    programCallParameter.ParameterValue = dynamicFieldData;
                    readOffset += (int)dynamicFieldLength;
                }
            }
            return (int)resultCode;
        }

        /// <summary>Performs a command call.</summary>
        /// <param name="commandString">CL command string</param>
        /// <param name="commandCallMessages">Output variable for command call's messages</param>
        /// <returns>Command call return code and output data (in the parameters variable)</returns>
        public int CallCommand(string commandString, ref CallMessages commandCallMessages)
        {
            // Establish command channel
            if (this.socketConnectorRemoteCommand == null)
                throw new System.InvalidOperationException("Operation failed, connection not established.");

            byte[] commandStringBytes;

            commandStringBytes = this.serverDatastreamLevel >= 10 ? Encoding.BigEndianUnicode.GetBytes(commandString) : Converters.AsciiToEbcdic(commandString);

            BigEndianMemoryStream outputStream = new BigEndianMemoryStream();
            outputStream.WriteShort(0); // Header ID.
            outputStream.WriteShort(ServerIDRemoteCommand); // Server ID.
            outputStream.WriteInt(0); // CS instance.
            outputStream.WriteInt(0); // Correlation ID.
            outputStream.WriteShort(1); // Template length.
            outputStream.WriteShort(0x1002); // ReqRep ID.

            byte messageOption;
            if (this.serverDatastreamLevel < 7)
                messageOption = 0;
            else if (this.serverDatastreamLevel < 10)
                messageOption = 2;
            else
                messageOption = 4;

            outputStream.WriteByte(messageOption);

            if (this.serverDatastreamLevel > 10)
            {
                outputStream.WriteInt((uint)(10 + commandStringBytes.Length)); // Command LL
                outputStream.WriteShort(0x1104); // Command CP
                outputStream.WriteShort(1200); // Command CCSID
                outputStream.Write(commandStringBytes, 0, commandStringBytes.Length); // Command
            }
            else
            {
                outputStream.WriteInt((uint)(6 + commandStringBytes.Length)); // Command LL
                outputStream.WriteShort(0x1101); // Command CP
                outputStream.Write(commandStringBytes, 0, commandStringBytes.Length); // Command
            }

            this.socketConnectorRemoteCommand.Write(outputStream.ToArray());

            // Retrieve server response
            byte[] response = this.socketConnectorRemoteCommand.Read();
            BigEndianMemoryStream inputStream = new BigEndianMemoryStream();
            inputStream.Write(response, 0, response.Length);
            /*
             *  The response comes  in the following format:
             * 
             *  Offset (byte)       Information         Length (byte)
             *  -----------------------------------------------------------
             *  Fixed header
             *  -----------------------------------------------------------
             *  0                   Response length     4
             *  4                   (Reserved)          16
             *  20                  Result code         2
             *  22                  Number of messages  2
             *
             *  -----------------------------------------------------------
             *  Dynamic fields (Offset is dynamic) - for Messages
             *  -----------------------------------------------------------
             *  0                   Message length      4
             *  4                   Message code        2
             *  6                   Message data        (Message length - 6)
             */

            // Read fixed header
            inputStream.Position = 0;
            uint responseLength = inputStream.ReadInt();
            if (responseLength < 20)
                throw new System.InvalidOperationException("Command call failed. Bad response length.");
            inputStream.Position += 16;

            ushort resultCode = inputStream.ReadShort();
            ushort returnedMessagesCount = inputStream.ReadShort();
            if (resultCode != 0 && resultCode != 0x0400)
                throw new System.InvalidOperationException("Command call failed, return code is 0x" + resultCode.ToString("X8"));

            if (commandCallMessages != null && returnedMessagesCount > 0)
            {
                byte[] outputMessages = new byte[responseLength - 24];
                inputStream.Read(outputMessages, 0, (int)responseLength - 24);
                commandCallMessages.FromByteStream(returnedMessagesCount, outputMessages);
            }

            Debug.WriteLine("Command " + commandString + " executed, return code is 0x" + resultCode.ToString("X8"));
            return (int)resultCode;
        }

        /// <summary>Performs a program call.</summary>
        /// <param name="serviceProgramName">Name of the service program</param>
        /// <param name="serviceProgramLibrary">Library where the service program is located</param>
        /// <param name="serviceFunction">Service program function to be called</param>
        /// <param name="serviceProgramCallParameters">Program's parameters</param>
        /// <param name="serviceProgramCallMessages">Output variable for program call's messages</param>
        /// <returns>Service program call return code</returns>
        public int CallServiceProgram(string serviceProgramName, string serviceProgramLibrary, string serviceFunction, ref ServiceProgramCallParameters serviceProgramCallParameters, ref CallMessages serviceProgramCallMessages)
        {
            if (serviceProgramName.Length > 10 || serviceProgramLibrary.Length > 10 || serviceProgramCallParameters == null)
                throw new System.InvalidOperationException("Wrong method invocation: service program name / library name cannot be longer than 10 characters.");

            /* 
             * The service program call is executed using QZRUCLSP API.
             * Please note that the implementation deviates from the standard description
             * for parameters passed by reference.
             * This is as the Remote Command Host Server will accept parameters "as-is",
             * and if needed invoke the QZRUCLSP providing an internal reference pointer.
             *
             * QZRUCLSP Parameters:
             * 
             * Required Parameter Group:
             * ---------------------------------------------------------------------
             *    1     Qualified service program name  Input   Char(20)
             *    2     Export Name                     Input   Char(*)
             *    3     Return Value Format             Input   Binary(4)
             *    4     Parameter Formats               Input   Array(*) of Binary(4)
             *    5     Number of Parameters            Input   Binary(4)
             *    6     Error code                      I/O     CHAR(*)
             *
             *       Optional Parameters:
             *
             *    7     Return Value                    Output  Char(*)
             *    8     Parameter 1                     I/O     Char(*)
             *    9     Parameter 2                     I/O     Char(*)
             *    10    Parameter 3                     I/O     Char(*)
             *    11    Parameter 4                     I/O     Char(*)
             *    12    Parameter 5                     I/O     Char(*)
             *    13    Parameter 6                     I/O     Char(*)
             *    14    Parameter 7                     I/O     Char(*)
             *       
             *  For Error code, the current implementation sets "Bytes provided" to 0,
             *  which will cause the call to fail if the function was not invoked properly.
             */

            ProgramCallParameters qzruclspProgramParameters = new ProgramCallParameters(7
                                                                + serviceProgramCallParameters.Length);

            for (int i = 0; i < 7 + serviceProgramCallParameters.Length; i++)
                qzruclspProgramParameters[i] = new ProgramCallParameter();

            qzruclspProgramParameters[0].ParameterType = ProgramCallParameter.ParameterTypeInput;
            qzruclspProgramParameters[0].ParameterValue = Converters.AsciiToEbcdic(serviceProgramName.Trim().ToUpper().PadRight(10) + 
                                                               serviceProgramLibrary.Trim().ToUpper().PadRight(10));
            qzruclspProgramParameters[0].ParameterMaxLength = 20;

            qzruclspProgramParameters[1].ParameterType = ProgramCallParameter.ParameterTypeInput;
            qzruclspProgramParameters[1].ParameterValue = Converters.AsciiToEbcdic(serviceFunction + "\0");
            qzruclspProgramParameters[1].ParameterMaxLength = (uint)serviceFunction.Length + 1;

            qzruclspProgramParameters[2].ParameterType = ProgramCallParameter.ParameterTypeInput;
            qzruclspProgramParameters[2].ParameterValue = Converters.UInt32ToBigEndian(serviceProgramCallParameters.ServiceProgramReturnValueFormat);
            qzruclspProgramParameters[2].ParameterMaxLength = 4;

            qzruclspProgramParameters[3].ParameterType = ProgramCallParameter.ParameterTypeInput;

            if (serviceProgramCallParameters.Length > 0)
            {
                using (BigEndianMemoryStream parameterFormatStream = new BigEndianMemoryStream())
                {
                    foreach (ServiceProgramCallParameter serviceProgramCallParameter in serviceProgramCallParameters)
                        parameterFormatStream.WriteInt(serviceProgramCallParameter.ParameterPassType);
                    qzruclspProgramParameters[3].ParameterValue = parameterFormatStream.ToArray();
                }
                qzruclspProgramParameters[3].ParameterMaxLength = 4 * (uint)serviceProgramCallParameters.Length;
            }
            else
            {
                qzruclspProgramParameters[3].ParameterValue = Converters.UInt32ToBigEndian(0);
                qzruclspProgramParameters[3].ParameterMaxLength = 4;
            }

            qzruclspProgramParameters[4].ParameterType = ProgramCallParameter.ParameterTypeInput;
            qzruclspProgramParameters[4].ParameterValue = Converters.UInt32ToBigEndian((uint)serviceProgramCallParameters.Length);
            qzruclspProgramParameters[4].ParameterMaxLength = 4;

            qzruclspProgramParameters[6].ParameterType = ProgramCallParameter.ParameterTypeOutput;
            switch (serviceProgramCallParameters.ServiceProgramReturnValueFormat)
            {
                case ServiceProgramCallParameters.ReturnValueIntegerErrno:
                    qzruclspProgramParameters[6].ParameterMaxLength = 8;
                    qzruclspProgramParameters[6].ParameterValue = new byte[8] { 0x00, 0x00, 0x00, 0x00,
                                                                                0x00, 0x00, 0x00, 0x00 };
                    break;
                case ServiceProgramCallParameters.ReturnValuePointer:
                    qzruclspProgramParameters[6].ParameterMaxLength = 16;
                    qzruclspProgramParameters[6].ParameterValue = new byte[16] { 0x00, 0x00, 0x00, 0x00,
                                                                                 0x00, 0x00, 0x00, 0x00,
                                                                                 0x00, 0x00, 0x00, 0x00,
                                                                                 0x00, 0x00, 0x00, 0x00 };
                    break;
                case ServiceProgramCallParameters.ReturnValueNone:
                case ServiceProgramCallParameters.ReturnValueInteger:
                default:
                    qzruclspProgramParameters[6].ParameterMaxLength = 4;
                    qzruclspProgramParameters[6].ParameterValue = new byte[4] { 0x00, 0x00, 0x00, 0x00 };
                    break;
            }

            qzruclspProgramParameters[5].ParameterType = ProgramCallParameter.ParameterTypeInputOutput;
            if (serviceProgramCallParameters.AlignReceiver16Bytes && serviceProgramCallParameters.Length > 0)
            {
                int qzruclspParametersLength = qzruclspProgramParameters[1].ParameterValue.Length
                                               + qzruclspProgramParameters[3].ParameterValue.Length
                                               + qzruclspProgramParameters[6].ParameterValue.Length
                                               + 28;

                qzruclspProgramParameters[5].ParameterValue = new byte[64 - (qzruclspParametersLength % 16)];
                qzruclspProgramParameters[5].ParameterMaxLength = (uint)qzruclspProgramParameters[5].ParameterValue.Length;
            }
            else
            {
                qzruclspProgramParameters[5].ParameterValue = Converters.UInt32ToBigEndian(0);
                qzruclspProgramParameters[5].ParameterMaxLength = 4;
            }

            for (int i = 0; i < serviceProgramCallParameters.Length; i++)
            {
                qzruclspProgramParameters[7 + i].ParameterType = ProgramCallParameter.ParameterTypeInputOutput;
                qzruclspProgramParameters[7 + i].ParameterValue = serviceProgramCallParameters[i].ParameterValue;
                qzruclspProgramParameters[7 + i].ParameterMaxLength = serviceProgramCallParameters[i].ParameterMaxLength;
            }

            int resultCode = this.CallProgram("QZRUCLSP", "QSYS", ref qzruclspProgramParameters, ref serviceProgramCallMessages);
            Debug.WriteLine("Service program " + serviceProgramLibrary.Trim() + "/" + serviceProgramName.Trim() + " function " + serviceFunction + " executed, return code is 0x" + resultCode.ToString("X8"));

            for (int i = 0; i < serviceProgramCallParameters.Length; i++)
                serviceProgramCallParameters[i].ParameterValue = qzruclspProgramParameters[7 + i].ParameterValue;

            switch (serviceProgramCallParameters.ServiceProgramReturnValueFormat)
            {
                case ServiceProgramCallParameters.ReturnValueIntegerErrno:
                    serviceProgramCallParameters.ReturnedValue = Converters.BigEndianToUInt32(qzruclspProgramParameters[6].ParameterValue, 0);
                    serviceProgramCallParameters.ReturnedErrno = Converters.BigEndianToUInt32(qzruclspProgramParameters[6].ParameterValue, 4);
                    serviceProgramCallParameters.ReturnedPointer = new byte[16] {0x00, 0x00, 0x00, 0x00,
                                                                                 0x00, 0x00, 0x00, 0x00,
                                                                                 0x00, 0x00, 0x00, 0x00,
                                                                                 0x00, 0x00, 0x00, 0x00 };
                    break;
                case ServiceProgramCallParameters.ReturnValueInteger:
                    serviceProgramCallParameters.ReturnedValue = Converters.BigEndianToUInt32(qzruclspProgramParameters[6].ParameterValue, 0);
                    serviceProgramCallParameters.ReturnedErrno = 0;
                    serviceProgramCallParameters.ReturnedPointer = new byte[16] {0x00, 0x00, 0x00, 0x00,
                                                                                 0x00, 0x00, 0x00, 0x00,
                                                                                 0x00, 0x00, 0x00, 0x00,
                                                                                 0x00, 0x00, 0x00, 0x00 };
                    break;
                case ServiceProgramCallParameters.ReturnValuePointer:
                    serviceProgramCallParameters.ReturnedValue = 0;
                    serviceProgramCallParameters.ReturnedErrno = 0;
                    serviceProgramCallParameters.ReturnedPointer = qzruclspProgramParameters[6].ParameterValue;
                    break;
                default:
                    serviceProgramCallParameters.ReturnedValue = 0;
                    serviceProgramCallParameters.ReturnedErrno = 0;
                    serviceProgramCallParameters.ReturnedPointer = new byte[16] {0x00, 0x00, 0x00, 0x00,
                                                                                 0x00, 0x00, 0x00, 0x00,
                                                                                 0x00, 0x00, 0x00, 0x00,
                                                                                 0x00, 0x00, 0x00, 0x00 };
                    break;
            }
            return resultCode;
        }

        //-----------------------------------------------------------------------
        // Helper classes
        //-----------------------------------------------------------------------

        /// <summary>
        /// Class CallMessages is used to store messages returned from Program calls.
        /// </summary>
        public class CallMessages : IEnumerable
        {
            //-----------------------------------------------------------------------
            // Class fields
            //-----------------------------------------------------------------------

            /// <summary>Holds information about the returned messages</summary>
            private CallMessage[] programCallMessages;

            //-----------------------------------------------------------------------
            // Class constructors
            //-----------------------------------------------------------------------

            /// <summary>Initializes a new instance of the <see cref="CallMessages"/> class.</summary>
            public CallMessages()
            {
            }

            //-----------------------------------------------------------------------
            // Class properties
            //-----------------------------------------------------------------------

            /// <summary>Gets information about the number of returned messages</summary>
            public int Length
            {
                get { return this.programCallMessages.Length; }
            }

            /// <summary>Gets information about the returned messages</summary>
            /// <param name="index">Message index</param>
            /// <returns>Message details</returns>
            public CallMessage this[int index]
            {
                get { return this.programCallMessages[index]; }
                internal set { this.programCallMessages[index] = value; }
            }

            //-----------------------------------------------------------------------
            // Enumerators
            //-----------------------------------------------------------------------

            /// <summary>Implements the enumerator for IEnumerable</summary>
            /// <returns>Enumerator for IEnumerable</returns>
            IEnumerator IEnumerable.GetEnumerator()
            {
                return (IEnumerator)this.GetEnumerator();
            }

            /// <summary>Implements the enumerator for CallMessages</summary>
            /// <returns>Enumerator for CallMessages</returns>
            public CallMessagesEnum GetEnumerator()
            {
                return new CallMessagesEnum(this.programCallMessages);
            }

            //-----------------------------------------------------------------------
            // Class methods
            //-----------------------------------------------------------------------

            /// <summary>Initializes the class with data from the byte stream</summary>
            /// <param name="messageCount">Number of returned messages</param>
            /// <param name="inputData">Byte stream input</param>
            internal void FromByteStream(int messageCount, byte[] inputData)
            {
                BigEndianMemoryStream inputStream = new BigEndianMemoryStream();
                inputStream.Write(inputData, 0, inputData.Length);
                /*
                 *  -----------------------------------------------------------
                 *  Dynamic fields (Offset is dynamic) - for Messages
                 *  -----------------------------------------------------------
                 *  0       Message length      4
                 *  4       Message code        2
                 *  6       Message data        (Message length - 6)
                 */

                // Read fixed header
                inputStream.Position = 0;

                this.programCallMessages = new CallMessage[messageCount];

                for (int i = 0; i < messageCount; i++)
                {
                    if (inputStream.Position >= inputStream.Length)
                        break;

                    uint messageLength = inputStream.ReadInt();
                    if (messageLength < 6)
                        throw new System.InvalidOperationException("Message import failed. Bad length.");

                    ushort messageCode = inputStream.ReadShort();
                    byte[] messageData = new byte[messageLength - 6];
                    inputStream.Read(messageData, 0, (int)(messageLength - 6));
                    this.programCallMessages[i] = new CallMessage(messageCode, messageData);
                }
            }
        }

        /// <summary>
        /// Class CallMessagesEnum is the implementation class for IEnumerator
        /// </summary>
        public class CallMessagesEnum : IEnumerator
        {
            //-----------------------------------------------------------------------
            // Class fields
            //-----------------------------------------------------------------------

            /// <summary>Holds the internal list of program call messages</summary>
            private CallMessage[] programCallMessages;

            /// <summary>Holds the internal counter</summary>
            private int position = -1;

            //-----------------------------------------------------------------------
            // Class constructors
            //-----------------------------------------------------------------------

            /// <summary>Initializes a new instance of the <see cref="CallMessagesEnum"/> class.</summary>
            /// <param name="programCallMessages">Returned messages</param>
            public CallMessagesEnum(CallMessage[] programCallMessages)
            {
                this.programCallMessages = programCallMessages;
            }

            //-----------------------------------------------------------------------
            // Properties
            //-----------------------------------------------------------------------

            /// <summary>Gets the current element.</summary>
            object IEnumerator.Current
            {
                get
                {
                    return this.Current;
                }
            }

            /// <summary>Gets and sets the current element.</summary>
            public CallMessage Current
            {
                get
                {
                    try
                    {
                        return this.programCallMessages[this.position];
                    }
                    catch (IndexOutOfRangeException)
                    {
                        throw new InvalidOperationException();
                    }
                }
            }

            //-----------------------------------------------------------------------
            // Class methods
            //-----------------------------------------------------------------------

            /// <summary>Moves to the next element.</summary>
            /// <returns>If false, the last element has been reached.</returns>
            public bool MoveNext()
            {
                this.position++;
                return this.position < this.programCallMessages.Length;
            }

            /// <summary>Resets the enumerator.</summary>
            public void Reset()
            {
                this.position = -1;
            }
        }

        /// <summary>
        /// Class CallMessage is used to store a single returned from Program calls.
        /// </summary>
        public class CallMessage
        {
            //-----------------------------------------------------------------------
            // Class constructors
            //-----------------------------------------------------------------------

            /// <summary>Initializes a new instance of the <see cref="CallMessage"/> class.</summary>
            /// <param name="messageCode">Message code (CP)</param>
            /// <param name="messageData">Byte stream input</param>
            internal CallMessage(ushort messageCode, byte[] messageData)
            {
                uint substitutionTextLength;
                uint substitutionTextOffset;
                uint messageTextLength;
                uint messageTextOffset;
                uint messageHelpTextLength;
                uint messageHelpTextOffset;
                uint messageTypeLength;
                uint messageIDLength;
                uint messageIDOffset;
                uint messageFileLength;
                uint messageFileOffset;
                uint messageLibraryLength;
                uint messageLibraryOffset;
                uint messageCcsid;
                uint substitutionCcsid;

                switch (messageCode)
                {
                    case 0x1102:
                        /*
                         *  -----------------------------------------------------------
                         *  Message structure for CP 0x1102
                         *  -----------------------------------------------------------
                         *  0       Message ID (EBCDIC)             7
                         *  7       Message type                    2
                         *  9       Message severity                2
                         *  11      Message file name               10
                         *  21      Message file library name       10
                         *  31      Length of substitution data     2
                         *  33      Length of message text          2
                         *  35      Substitution text               (Length of substitution text)
                         *  ()      Message text                    (Length of message text)
                         */

                        substitutionTextLength = Converters.BigEndianToUInt16(messageData, 31);
                        messageTextLength = Converters.BigEndianToUInt16(messageData, 33);

                        this.MessageID = Converters.EbcdicToAsciiString(messageData, 0, 7);
                        this.MessageType = Converters.BigEndianToUInt16(messageData, 7);
                        this.MessageSeverity = Converters.BigEndianToUInt16(messageData, 9);
                        this.MessageSubstitutionText = Converters.EbcdicToAsciiString(messageData, 35, substitutionTextLength);
                        this.MessageText = Converters.EbcdicToAsciiString(messageData, 35 + substitutionTextLength, messageTextLength);
                        this.MessageHelpText = string.Empty;
                        break;
                    case 0x1106:
                        /*
                         *  -----------------------------------------------------------
                         *  Message structure for CP 0x1106
                         *  -----------------------------------------------------------
                         *  0       Message text CCSID                      4
                         *  4       Message substitution CCSID              4
                         *  8       Message severity                        2
                         *  10      Length of message type                  4
                         *  14      Message type                            2
                         *  ()      (Reserved)                              (Length of message type - 2)
                         *  ()      Length of message ID                    4
                         *  ()      Message ID (EBCDIC)                     (Length of message ID)
                         *  ()      Length of message file name             4
                         *  ()      Message file name                       (Length of message file name)
                         *  ()      Length of message file library name     10
                         *  ()      Message file library name               (Length of message file library name)
                         *  ()      Length of message text                  4
                         *  ()      Message text                            (Length of message text)
                         *  ()      Length of substitution text             4
                         *  ()      Substitution text                       (Length of substitution text)
                         *  ()      Length of message help text             4
                         *  ()      Message help text                       (Length of message help text)
                         */
                        messageCcsid = Converters.BigEndianToUInt32(messageData, 0);
                        substitutionCcsid = Converters.BigEndianToUInt32(messageData, 4);
                        messageTypeLength = Converters.BigEndianToUInt32(messageData, 10);
                        messageIDLength = Converters.BigEndianToUInt32(messageData, 14 + messageTypeLength);
                        messageIDOffset = 18 + messageTypeLength;
                        messageFileLength = Converters.BigEndianToUInt32(messageData, messageIDOffset + messageIDLength);
                        messageFileOffset = (messageIDOffset + messageIDLength) + 4;
                        messageLibraryLength = Converters.BigEndianToUInt32(messageData, messageFileOffset + messageFileLength);
                        messageLibraryOffset = (messageFileOffset + messageFileLength) + 4;
                        messageTextLength = Converters.BigEndianToUInt32(messageData, messageLibraryOffset + messageLibraryLength);
                        messageTextOffset = (messageLibraryOffset + messageLibraryLength) + 4;
                        substitutionTextLength = Converters.BigEndianToUInt32(messageData, messageTextOffset + messageTextLength);
                        substitutionTextOffset = (messageTextOffset + messageTextLength) + 4;
                        messageHelpTextLength = Converters.BigEndianToUInt32(messageData, substitutionTextOffset + substitutionTextLength);
                        messageHelpTextOffset = (substitutionTextOffset + substitutionTextLength) + 4;

                        this.MessageID = Converters.EbcdicToAsciiString(messageData, messageIDOffset, messageIDLength); //// , (int)messageCcsid);
                        this.MessageType = Converters.BigEndianToUInt16(messageData, 14);
                        this.MessageSeverity = Converters.BigEndianToUInt16(messageData, 8);
                        this.MessageSubstitutionText = Converters.EbcdicToAsciiString(messageData, substitutionTextOffset, substitutionTextLength); //// , (int)substitutionCcsid);
                        this.MessageText = Converters.EbcdicToAsciiString(messageData, messageTextOffset, messageTextLength); //// , (int)messageCcsid);
                        this.MessageHelpText = Converters.EbcdicToAsciiString(messageData, messageHelpTextOffset, messageHelpTextLength); //// , (int)messageCcsid);
                        break;
                    default:
                        break;
                }
            }

            //-----------------------------------------------------------------------
            // Properties
            //-----------------------------------------------------------------------

            /// <summary>Gets information about the message ID</summary>
            public string MessageID { get; }

            /// <summary>Gets information about the message type</summary>
            public int MessageType { get; }

            /// <summary>Gets information about the message text</summary>
            public string MessageText { get; }

            /// <summary>Gets information about the message text</summary>
            public string MessageSubstitutionText { get; }

            /// <summary>Gets information about the message severity</summary>
            public int MessageSeverity { get; }

            /// <summary>Gets information about the message help text</summary>
            public string MessageHelpText { get; }

            //-----------------------------------------------------------------------
            // Class methods
            //-----------------------------------------------------------------------
        }

        /// <summary>
        /// Class ProgramCallParameters is used to store parameters required for Program calls.
        /// </summary>
        public class ProgramCallParameters : IEnumerable
        {
            //-----------------------------------------------------------------------
            // Class fields
            //-----------------------------------------------------------------------

            /// <summary>Holds information about the returned messages</summary>
            private ProgramCallParameter[] programCallParameters;

            //-----------------------------------------------------------------------
            // Class constructors
            //-----------------------------------------------------------------------

            /// <summary>Initializes a new instance of the <see cref="ProgramCallParameters"/> class.</summary>
            /// <param name="count">Number of parameters</param>
            public ProgramCallParameters(int count)
            {
                this.programCallParameters = new ProgramCallParameter[count];
            }

            //-----------------------------------------------------------------------
            // Class properties
            //-----------------------------------------------------------------------

            /// <summary>Gets information about the number of parameters</summary>
            public int Length
            {
                get { return this.programCallParameters.Length; }
            }

            /// <summary>Gets information about the specific parameter</summary>
            /// <param name="index">Message index</param>
            /// <returns>Parameter details</returns>
            public ProgramCallParameter this[int index]
            {
                get { return this.programCallParameters[index]; }
                set { this.programCallParameters[index] = value; }
            }

            //-----------------------------------------------------------------------
            // Enumerators
            //-----------------------------------------------------------------------

            /// <summary>Implements the enumerator for IEnumerable</summary>
            /// <returns>Enumerator for IEnumerable</returns>
            IEnumerator IEnumerable.GetEnumerator()
            {
                return (IEnumerator)this.GetEnumerator();
            }

            /// <summary>Implements the enumerator for IEnumerable</summary>
            /// <returns>Enumerator for ProgramCallParameters</returns>
            public ProgramCallParametersEnum GetEnumerator()
            {
                return new ProgramCallParametersEnum(this.programCallParameters);
            }
        }

        /// <summary>
        /// Class ProgramCallParametersEnum is the implementation class for IEnumerator
        /// </summary>
        public class ProgramCallParametersEnum : IEnumerator
        {
            //-----------------------------------------------------------------------
            // Class fields
            //-----------------------------------------------------------------------

            /// <summary>Holds the internal list of program call messages</summary>
            private ProgramCallParameter[] programCallParameters;

            /// <summary>Holds the internal counter</summary>
            private int position = -1;

            //-----------------------------------------------------------------------
            // Class constructors
            //-----------------------------------------------------------------------

            /// <summary>Initializes a new instance of the <see cref="ProgramCallParametersEnum"/> class.</summary>
            /// <param name="programCallParameters">Returned messages</param>
            public ProgramCallParametersEnum(ProgramCallParameter[] programCallParameters)
            {
                this.programCallParameters = programCallParameters;
            }

            //-----------------------------------------------------------------------
            // Properties
            //-----------------------------------------------------------------------

            /// <summary>Gets the current element.</summary>
            object IEnumerator.Current
            {
                get
                {
                    return this.Current;
                }
            }

            /// <summary>Gets and sets the current element.</summary>
            public ProgramCallParameter Current
            {
                get
                {
                    try
                    {
                        return this.programCallParameters[this.position];
                    }
                    catch (IndexOutOfRangeException)
                    {
                        throw new InvalidOperationException();
                    }
                }
            }

            //-----------------------------------------------------------------------
            // Class methods
            //-----------------------------------------------------------------------

            /// <summary>Moves to the next element.</summary>
            /// <returns>If false, the last element has been reached.</returns>
            public bool MoveNext()
            {
                this.position++;
                return this.position < this.programCallParameters.Length;
            }

            /// <summary>Resets the enumerator.</summary>
            public void Reset()
            {
                this.position = -1;
            }
        }

        /// <summary>
        /// Class ProgramCallParameter is used to store single parameter used for Program calls.
        /// </summary>
        public class ProgramCallParameter
        {
            //-----------------------------------------------------------------------
            // Constants
            //-----------------------------------------------------------------------

            /// <summary>Parameter type: NULL</summary>
            public const ushort ParameterTypeNull = 255;

            /// <summary>Parameter type: Input</summary>
            public const ushort ParameterTypeInput = 11;

            /// <summary>Parameter type: Output</summary>
            public const ushort ParameterTypeOutput = 12;

            /// <summary>Parameter type: Input/Output</summary>
            public const ushort ParameterTypeInputOutput = 13;

            //-----------------------------------------------------------------------
            // Class fields
            //-----------------------------------------------------------------------

            /// <summary>Holds information about the parameter's type</summary>
            private ushort parameterType;

            /// <summary>Holds information about the (output) parameter's maximum length</summary>
            private uint parameterMaxLength;

            //-----------------------------------------------------------------------
            // Class methods
            //-----------------------------------------------------------------------

            /// <summary>Initializes a new instance of the <see cref="ProgramCallParameter"/> class.</summary>
            /// <param name="parameterType">Predefined parameter type (NULL, Input, Output, Input/Output)</param>
            /// <param name="parameterValue">Value of the parameter</param>
            /// <param name="maxLength">Maximum length of the output parameter (only for Output and Input/Output parameters)</param>
            public ProgramCallParameter(ushort parameterType, byte[] parameterValue = null, uint maxLength = 0)
            {
                this.ParameterType = parameterType;
                this.ParameterValue = parameterValue;
                this.ParameterMaxLength = maxLength;
            }

            /// <summary>Initializes a new instance of the <see cref="ProgramCallParameter"/> class.</summary>
            public ProgramCallParameter()
            {
            }

            //-----------------------------------------------------------------------
            // Properties
            //-----------------------------------------------------------------------

            /// <summary>Gets or sets information about the parameter's type</summary>
            public ushort ParameterType
            {
                get
                {
                    return this.parameterType;
                }

                set
                {
                    if (value != ParameterTypeNull &&
                        value != ParameterTypeInput &&
                        value != ParameterTypeOutput &&
                        value != ParameterTypeInputOutput)
                        this.parameterType = ParameterTypeInputOutput;

                    this.parameterType = value;
                }
            }

            /// <summary>Gets or sets information about the parameter's type</summary>
            public uint ParameterMaxLength
            {
                get
                {
                    switch (this.ParameterType)
                    {
                        case ParameterTypeOutput:
                            return this.parameterMaxLength;
                        case ParameterTypeInputOutput:
                            if (this.ParameterValue == null) return this.parameterMaxLength;
                            return this.ParameterValue.Length > this.parameterMaxLength ? (uint)this.ParameterValue.LongLength : this.parameterMaxLength;
                        case ParameterTypeNull:
                            return 0;
                        case ParameterTypeInput:
                        default:
                            if (this.ParameterValue == null) return this.parameterMaxLength;
                            return (uint)this.ParameterValue.LongLength;
                    }
                }

                set
                {
                    switch (this.ParameterType)
                    {
                        case ParameterTypeInputOutput:
                        case ParameterTypeOutput:
                            this.parameterMaxLength = value;
                            break;
                        default:
                            if (this.ParameterValue == null)
                                this.parameterMaxLength = 0;
                            else
                                this.parameterMaxLength = (uint)this.ParameterValue.LongLength;
                            break;
                    }
                }
            }

            /// <summary>Gets or sets information about the parameter's value</summary>
            public byte[] ParameterValue { get; set; }
        }

        /// <summary>
        /// Class ServiceProgramCallParameters is used to store parameters required for Service Program calls.
        /// </summary>
        public class ServiceProgramCallParameters : IEnumerable
        {
            //-----------------------------------------------------------------------
            // Constants
            //-----------------------------------------------------------------------

            /// <summary>Function does not return a value.</summary>
            public const uint ReturnValueNone = 0;

            /// <summary>Function returns an Integer value.</summary>
            public const ushort ReturnValueInteger = 1;

            /// <summary>Function returns a 16-byte pointer.</summary>
            public const ushort ReturnValuePointer = 2;

            /// <summary>Function returns an Integer value and a "errno" value.</summary>
            public const ushort ReturnValueIntegerErrno = 3;

            //-----------------------------------------------------------------------
            // Class fields
            //-----------------------------------------------------------------------

            /// <summary>Holds information about the parameters</summary>
            private ServiceProgramCallParameter[] serviceProgramCallParameters;

            //-----------------------------------------------------------------------
            // Class constructors
            //-----------------------------------------------------------------------

            /// <summary>Initializes a new instance of the <see cref="ServiceProgramCallParameters"/> class.</summary>
            /// <param name="count">Number of parameters</param>
            public ServiceProgramCallParameters(int count)
            {
                if (count > 7)
                    throw new System.InvalidOperationException("Service program can accept only 7 parameters.");

                this.serviceProgramCallParameters = new ServiceProgramCallParameter[count];
                for (int i = 0; i < count; i++)
                    this.serviceProgramCallParameters[i] = new ServiceProgramCallParameter();

                this.AlignReceiver16Bytes = false;
            }

            //-----------------------------------------------------------------------
            // Class properties
            //-----------------------------------------------------------------------

            /// <summary>Gets or sets information about the service program's return value format</summary>
            public uint ServiceProgramReturnValueFormat { get; set; }

            /// <summary>Gets or sets a value indicating whether to use the 16-byte alignment for the first parameter (Receiver variable)</summary>
            public bool AlignReceiver16Bytes { get; set; }

            /// <summary>Gets information about the returned value</summary>
            public uint ReturnedValue { get; internal set; }

            /// <summary>Gets information about the returned errno</summary>
            public uint ReturnedErrno { get; internal set; }

            /// <summary>Gets information about the returned pointer</summary>
            public byte[] ReturnedPointer { get; internal set; }

            /// <summary>Gets information about the number of parameters</summary>
            public int Length
            {
                get { return this.serviceProgramCallParameters.Length; }
            }

            /// <summary>Gets information about the specific parameter</summary>
            /// <param name="index">Message index</param>
            /// <returns>Parameter details</returns>
            public ServiceProgramCallParameter this[int index]
            {
                get { return this.serviceProgramCallParameters[index]; }
                set { this.serviceProgramCallParameters[index] = value; }
            }

            //-----------------------------------------------------------------------
            // Enumerators
            //-----------------------------------------------------------------------

            /// <summary>Implements the enumerator for IEnumerable</summary>
            /// <returns>Enumerator for IEnumerable</returns>
            IEnumerator IEnumerable.GetEnumerator()
            {
                return (IEnumerator)this.GetEnumerator();
            }

            /// <summary>Implements the enumerator for IEnumerable</summary>
            /// <returns>Enumerator for ServiceProgramCallParameters</returns>
            public ServiceProgramCallParametersEnum GetEnumerator()
            {
                return new ServiceProgramCallParametersEnum(this.serviceProgramCallParameters);
            }
        }

        /// <summary>
        /// Class ServiceProgramCallParametersEnum is the implementation class for IEnumerator
        /// </summary>
        public class ServiceProgramCallParametersEnum : IEnumerator
        {
            //-----------------------------------------------------------------------
            // Class fields
            //-----------------------------------------------------------------------

            /// <summary>Holds the internal list of program call messages</summary>
            private ServiceProgramCallParameter[] serviceProgramCallParameters;

            /// <summary>Holds the internal counter</summary>
            private int position = -1;

            //-----------------------------------------------------------------------
            // Class constructors
            //-----------------------------------------------------------------------

            /// <summary>Initializes a new instance of the <see cref="ServiceProgramCallParametersEnum"/> class.</summary>
            /// <param name="serviceProgramCallParameters">Returned messages</param>
            public ServiceProgramCallParametersEnum(ServiceProgramCallParameter[] serviceProgramCallParameters)
            {
                this.serviceProgramCallParameters = serviceProgramCallParameters;
            }

            //-----------------------------------------------------------------------
            // Properties
            //-----------------------------------------------------------------------

            /// <summary>Gets the current element.</summary>
            object IEnumerator.Current
            {
                get
                {
                    return this.Current;
                }
            }

            /// <summary>Gets and sets the current element.</summary>
            public ServiceProgramCallParameter Current
            {
                get
                {
                    try
                    {
                        return this.serviceProgramCallParameters[this.position];
                    }
                    catch (IndexOutOfRangeException)
                    {
                        throw new InvalidOperationException();
                    }
                }
            }

            //-----------------------------------------------------------------------
            // Class methods
            //-----------------------------------------------------------------------

            /// <summary>Moves to the next element.</summary>
            /// <returns>If false, the last element has been reached.</returns>
            public bool MoveNext()
            {
                this.position++;
                return this.position < this.serviceProgramCallParameters.Length;
            }

            /// <summary>Resets the enumerator.</summary>
            public void Reset()
            {
                this.position = -1;
            }
        }

        /// <summary>
        /// Class ServiceProgramCallParameter is used to store single parameter used for Program calls.
        /// </summary>
        public class ServiceProgramCallParameter
        {
            //-----------------------------------------------------------------------
            // Constants
            //-----------------------------------------------------------------------

            /// <summary>Parameter should be passed by value (only for 4 byte parameters)</summary>
            public const ushort ParameterPassByValue = 1;

            /// <summary>Parameter should be passed by reference (handled automatically on server side)</summary>
            public const ushort ParameterPassByReference = 2;

            //-----------------------------------------------------------------------
            // Class fields
            //-----------------------------------------------------------------------

            /// <summary>Holds information about the parameter's passing type (by value or reference)</summary>
            private ushort parameterPassType;

            /// <summary>Holds information about the (output) parameter's maximum length</summary>
            private uint parameterMaxLength;

            //-----------------------------------------------------------------------
            // Class methods
            //-----------------------------------------------------------------------

            /// <summary>Initializes a new instance of the <see cref="ServiceProgramCallParameter"/> class.</summary>
            /// <param name="parameterPassType">Predefined parameter passing type (by value or reference)</param>
            /// <param name="parameterValue">Value of the parameter</param>
            /// <param name="maxLength">Maximum length of the output parameter (only for Output and Input/Output parameters)</param>
            public ServiceProgramCallParameter(ushort parameterPassType, byte[] parameterValue = null, uint maxLength = 0)
            {
                this.ParameterPassType = parameterPassType;
                this.ParameterValue = parameterValue;
                this.ParameterMaxLength = maxLength;
            }

            /// <summary>Initializes a new instance of the <see cref="ServiceProgramCallParameter"/> class.</summary>
            public ServiceProgramCallParameter()
            {
            }

            //-----------------------------------------------------------------------
            // Properties
            //-----------------------------------------------------------------------

            /// <summary>Gets or sets information about the parameter's type</summary>
            public ushort ParameterPassType
            {
                get
                {
                    return this.parameterPassType;
                }

                set
                {
                    if (value != ParameterPassByValue &&
                        value != ParameterPassByReference)
                        this.parameterPassType = ParameterPassByReference;

                    this.parameterPassType = value;
                }
            }

            /// <summary>Gets or sets information about the parameter's type</summary>
            public uint ParameterMaxLength
            {
                get
                {
                    if (this.ParameterValue == null)
                        return this.parameterMaxLength;

                    return this.ParameterValue.Length > this.parameterMaxLength ? (uint)this.ParameterValue.LongLength : this.parameterMaxLength;
                }

                set
                {
                    this.parameterMaxLength = value;
                }
            }

            /// <summary>Gets or sets information about the parameter's value</summary>
            public byte[] ParameterValue { get; set; }
        }
    }
}

//-----------------------------------------------------------------------
// <copyright file="IBMiConnector.Connectivity.cs" company="Bart Kulach">
// Copyright (C) 2018-2019 Bart Kulach
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
    using System.Diagnostics;

    /// <content>
    /// This file implements methods related to connectivity.
    /// </content>
    public partial class IBMiConnector
    {
        //-----------------------------------------------------------------------
        // Class fields
        //-----------------------------------------------------------------------

        /// <summary>Holds the socket connector instance used for socket communication with the sign-on verification service</summary>
        private SocketConnector socketConnectorSignonVerify = null;

        /// <summary>Holds the socket connector instance used for socket communication with the remote command service</summary>
        private SocketConnector socketConnectorRemoteCommand = null;

        /// <summary>Holds the current client seed</summary>
        private ulong clientSeed = 0;

        /// <summary>Holds the currrent server seed</summary>
        private ulong serverSeed = 0;

        //-----------------------------------------------------------------------
        // Class methods
        //-----------------------------------------------------------------------

        /// <summary>Establishes connection with an IBM i system.</summary>
        public void Connect()
        {
            // Exchange seeds and get session information
            this.ConnectToSignonVerifyServer();

            // Authenticate user to the Signon server
            this.AuthenticateToSignonVerifyServer();

            // Connect to the Remote command server and exchange seeds 
            this.ConnectToRemoteCommandServer();

            // Authenticate user to the Remote Command server
            this.AuthenticateToRemoteCommandServer();

            // Get session information
            this.RetrieveRemoteCommandServerInformation();

            Debug.WriteLine("Connection to " + this.serverName + " established, job name " + this.jobName);
        }

        /// <summary>Ends connection with an IBM i system.</summary>
        public void Disconnect()
        {
            // TODO - code
            this.socketConnectorSignonVerify?.Disconnect();
            this.socketConnectorSignonVerify = null;
            this.socketConnectorRemoteCommand?.Disconnect();
            this.socketConnectorRemoteCommand = null;
            this.jobName = string.Empty;

            Debug.WriteLine("Connection with " + this.serverName + " was closed.");
        }

        //-----------------------------------------------------------------------
        // Private methods
        //-----------------------------------------------------------------------

        /// <summary>Connects to the Sign-on Verify server</summary>
        private void ConnectToSignonVerifyServer()
        {
            // Establish authentication channel
            this.socketConnectorSignonVerify = new SocketConnector(this.serverName, this.useSSL ? TcpPortSignonVerifySSL : TcpPortSignonVerify, this.useSSL, this.ignoreSelfSignedCertificates);

            // Default current seed information
            this.clientSeed = 0;
            this.serverSeed = 0;

            // Exchange random seeds
            ulong clientSeed = (ulong)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
            BigEndianMemoryStream outputStream = new BigEndianMemoryStream();
 ////           outputStream.WriteInt(52); // length
            outputStream.WriteShort(0); // Header ID (0)
            outputStream.WriteShort(ServerIDSignonVerify); // Server ID
            outputStream.WriteInt(0); // CS instance
            outputStream.WriteInt(0); // Correlation ID
            outputStream.WriteShort(0);  // Template length
            outputStream.WriteShort(0x7003);  // ReqReP ID
            outputStream.WriteInt(10);  // Client version LL
            outputStream.WriteShort(0x1101); // Client version CP
            outputStream.WriteInt(1);  // Client version
            outputStream.WriteInt(8);  // Client data stream level LL
            outputStream.WriteShort(0x1102);  // Client datastream level CP 
            outputStream.WriteShort(2); // Client datastream level
            outputStream.WriteInt(14); // Client seed LL
            outputStream.WriteShort(0x1103); // Client seed CP
            outputStream.WriteLong(clientSeed); // Client seed
            this.socketConnectorSignonVerify.Write(outputStream.ToArray());

            // Retrieve server response
            byte[] response = this.socketConnectorSignonVerify.Read();
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
             *  20                  Result code         4
             *  24                  (Dynamic fields)    see below
             *  -----------------------------------------------------------
             *  Dynamic fields (Offset is dynamic)
             *  -----------------------------------------------------------
             *  0                   Field length        4
             *  4                   Field code          2
             *  6                   Field data          (Field length - 6)
             */

            // Read fixed header
            inputStream.Position = 0;
            uint responseLength = inputStream.ReadInt();
            if (responseLength < 20)
                throw new System.InvalidOperationException("Seeds exchange failed. Bad response length.");

            inputStream.Position += 16;

            uint resultCode = inputStream.ReadInt();
            if (resultCode != 0)
                throw new System.InvalidOperationException("Seeds exchange failed. Bad return code.");

            while (inputStream.Position < responseLength)
            {
                uint dynamicFieldLength = inputStream.ReadInt();
                ushort dynamicFieldCode = inputStream.ReadShort();
                byte[] dynamicFieldData = new byte[dynamicFieldLength - 6];
                inputStream.Read(dynamicFieldData, 0, (int)dynamicFieldLength - 6);

                switch (dynamicFieldCode)
                {
                    case 0x1101:    // Server Version
                        this.serverVersion = Converters.BigEndianToUInt32(dynamicFieldData);
                        break;
                    case 0x1102:    // Server Level
                        this.serverLevel = Converters.BigEndianToUInt16(dynamicFieldData);
                        break;
                    case 0x1103:    // Server Seed
                        this.serverSeed = Converters.BigEndianToUInt64(dynamicFieldData);
                        break;
                    case 0x1119:    // Password Level
                        this.passwordLevel = Converters.BigEndianToUInt8(dynamicFieldData);
                        break;
                    case 0x111F:    // Job Name
                        this.jobName = Converters.EbcdicToAsciiString(dynamicFieldData, 4);
                        break;
                    default:
                        break;
                }
            }

            Debug.WriteLine("Seeds were exchanged, return code is 0x" + resultCode.ToString("X8"));

            this.clientSeed = clientSeed;
        }

        /// <summary>Connects to the Remote Command server</summary>
        private void ConnectToRemoteCommandServer()
        {
            // Establish command channel
            this.socketConnectorRemoteCommand = new SocketConnector(this.serverName, this.useSSL ? TcpPortRemoteCommandSSL : TcpPortRemoteCommand, this.useSSL, this.ignoreSelfSignedCertificates);

            // Default current seed information
            this.clientSeed = 0;
            this.serverSeed = 0;

            // Exchange random seeds
            ulong clientSeed = (ulong)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
            BigEndianMemoryStream outputStream = new BigEndianMemoryStream();
            outputStream.WriteByte(1); // Client attributes (1 = SHA-1 capability enabled)
            outputStream.WriteByte(0); // Server attributes
            outputStream.WriteShort(ServerIDRemoteCommand); // Server ID
            outputStream.WriteInt(0); // CS instance
            outputStream.WriteInt(0); // Correlation ID
            outputStream.WriteShort(8);  // Template length
            outputStream.WriteShort(0x7001);  // ReqReP ID
            outputStream.WriteLong(clientSeed); // Client seed
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
             *  20                  Result code         4
             *  24                  Server seed         8
             */

            // Read fixed header
            inputStream.Position = 0;
            uint responseLength = inputStream.ReadInt();
            if (responseLength < 20)
                throw new System.InvalidOperationException("Seeds exchange failed. Bad response length.");

            inputStream.Position += 16;

            uint resultCode = inputStream.ReadInt();
            if (resultCode != 0)
                throw new System.InvalidOperationException("Seeds exchange failed. Bad return code.");

            this.serverSeed = inputStream.ReadLong();
            this.clientSeed = clientSeed;

            Debug.WriteLine("Seeds were exchanged, return code is 0x" + resultCode.ToString("X8"));
        }

        /// <summary>Retrieves server information</summary>
        private void RetrieveRemoteCommandServerInformation()
        {
            // Establish command channel
            if (this.socketConnectorRemoteCommand == null)
                throw new System.InvalidOperationException("Operation failed, connection not established.");

            BigEndianMemoryStream outputStream = new BigEndianMemoryStream();
            outputStream.WriteShort(0); // Header ID
            outputStream.WriteShort(ServerIDRemoteCommand); // Server ID
            outputStream.WriteInt(0); // CS instance
            outputStream.WriteInt(0); // Correlation ID
            outputStream.WriteShort(14);  // Template length
            outputStream.WriteShort(0x1001);  // ReqReP ID
            outputStream.WriteInt(1200); // Operation is CCSID
            outputStream.Write(Converters.AsciiToEbcdic("2924"), 0, 4); // NLV value (default = 2924 = English)
            outputStream.WriteInt(1); // Client version
            outputStream.WriteShort(0);  // Client datastream level
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
             *  24                  CCSID               4
             *  28                  NLV (in EBCDIC)     4
             *  32                  (reserved)          4
             *  36                  Datastream level    2
             */

            // Read fixed header
            inputStream.Position = 0;
            uint responseLength = inputStream.ReadInt();
            if (responseLength < 20)
                throw new System.InvalidOperationException("Seeds exchange failed. Bad response length.");

            inputStream.Position += 16;

            uint resultCode = inputStream.ReadShort();

            // We ignore the same return codes that JTOPEN/JT400 ignores
            if (resultCode != 0x0100 &&  // User with *LMTCPB = *YES
                resultCode != 0x0104 &&  // Invalid CCSID.
                resultCode != 0x0105 &&  // Invalid NLV, default to primary NLV:  
                resultCode != 0x0106 &&  // NLV not installed, default to primary NLV:  
                                         // The NLV may not be supported or it may not be installed on the system.
                resultCode != 0x0107 &&  // Error retrieving product information.  Can't validate NLV.
                resultCode != 0x0108 &&  // Error trying to add NLV library to system library list:  
                                         // One possible reason for failure is the user may not be authorized to CHGSYSLIBL command.
                resultCode != 0)
                throw new System.InvalidOperationException("Invalid operation, failed to retrieve Remote Command server attributes.");

            this.serverCCSID = inputStream.ReadInt();
            byte[] nlv = new byte[4];
            inputStream.Read(nlv, 0, 4);
            this.serverNLV = Converters.EbcdicToAsciiString(nlv);
            inputStream.Position += 4;
            this.serverDatastreamLevel = inputStream.ReadShort();

            Debug.WriteLine("Remote Command server attributes retrieved, return code is 0x" + resultCode.ToString("X8"));
        }

        /// <summary>Authenticates the user to the signon server</summary>
        private void AuthenticateToSignonVerifyServer()
        {
            BigEndianMemoryStream outputStream = new BigEndianMemoryStream();
            byte[] encryptedPassword;
            byte[] userID = Converters.AsciiToEbcdic(this.userName.ToUpper().PadRight(10));
            encryptedPassword = this.passwordLevel <= 2 ? Encryption.EncryptPasswordDES(this.userName, this.password, this.serverSeed, this.clientSeed) : Encryption.EncryptPasswordSHA1(this.userName, this.password, this.serverSeed, this.clientSeed);

            if (this.serverLevel >= 5)
            outputStream.WriteShort(0); // Header ID (0)
            outputStream.WriteShort(ServerIDSignonVerify); // Server ID
            outputStream.WriteInt(0); // CS instance
            outputStream.WriteInt(0); // Correlation ID
            outputStream.WriteShort(0x0001);  // Template length
            outputStream.WriteShort(0x7004);  // ReqReP ID
            outputStream.WriteByte((byte)(this.passwordLevel < 2 ? 1 : 3)); // Password encryption type
            outputStream.WriteInt(10);  // Client CCSID LL
            outputStream.WriteShort(0x1113); // Client CCSID CP
            outputStream.WriteInt(1200);  // Client CCSID (big endian UTF-16)
            outputStream.WriteInt(6 + (uint)encryptedPassword.Length);  // Password LL
            outputStream.WriteShort(0x1105);  // Password CP. 0x1115 is other. 
            outputStream.Write(encryptedPassword, 0, encryptedPassword.Length); // Password
            outputStream.WriteInt(16); // User ID LL
            outputStream.WriteShort(0x1104); // User ID CP
            outputStream.Write(userID, 0, userID.Length); // UserID
            if (this.serverLevel >= 5)
            {
                outputStream.WriteInt(7); // Return error messages LL
                outputStream.WriteShort(0x1128);  // Return error messages CP
                outputStream.WriteByte(1); // Return error messages
            }

            this.socketConnectorSignonVerify.Write(outputStream.ToArray());

            // Retrieve server response
            byte[] response = this.socketConnectorSignonVerify.Read();
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
             *  20                  Result code         4
             *  24                  (Dynamic fields)    see below
             *  -----------------------------------------------------------
             *  Dynamic fields (Offset is dynamic)
             *  -----------------------------------------------------------
             *  0                   Field length        4
             *  4                   Field code          2
             *  6                   Field data          (Field length - 6)
             */

            // Read fixed header
            inputStream.Position = 0;
            uint responseLength = inputStream.ReadInt();
            if (responseLength < 20)
                throw new System.InvalidOperationException("Authentication failed. Bad response length.");

            inputStream.Position += 16;

            uint resultCode = inputStream.ReadInt();
            if (resultCode != 0)
            {
                switch (resultCode)
                {
                    case 0x00020001:
                        throw new System.InvalidOperationException("Authentication failed. Unknown username.");
                    case 0x0003000B:
                        throw new System.InvalidOperationException("Authentication failed. Wrong password.");
                    case 0x0003000C:
                        throw new System.InvalidOperationException("Authentication failed. Wrong password. Profile will be disabled on the next invalid password.");
                    case 0x0003000D:
                        throw new System.InvalidOperationException("Authentication failed. Password is expired.");
                    case 0x00030010:
                        throw new System.InvalidOperationException("Authentication failed. Password is *NONE.");
                    default:
                        throw new System.InvalidOperationException("Authentication failed. Return code 0x" + resultCode.ToString("X8"));
                }
            }                

            while (inputStream.Position < responseLength)
            {
                uint dynamicFieldLength = inputStream.ReadInt();
                ushort dynamicFieldCode = inputStream.ReadShort();
                byte[] dynamicFieldData = new byte[dynamicFieldLength - 6];
                inputStream.Read(dynamicFieldData, 0, (int)dynamicFieldLength - 6);

                switch (dynamicFieldCode)
                {
                    case 0x1114:    // Server Version
                        this.serverCCSID = Converters.BigEndianToUInt32(dynamicFieldData);
                        break;
                    default:
                        break;
                }
            }

            Debug.WriteLine("User authenticated to signon server.");
        }

        /// <summary>Authenticates the user to the remote command server</summary>
        private void AuthenticateToRemoteCommandServer()
        {
            // Establish command channel
            if (this.socketConnectorRemoteCommand == null)
                throw new System.InvalidOperationException("Operation failed, connection not established.");

            BigEndianMemoryStream outputStream = new BigEndianMemoryStream();
            byte[] encryptedPassword;
            byte[] userID = Converters.AsciiToEbcdic(this.userName.ToUpper().PadRight(10));
            encryptedPassword = this.passwordLevel <= 2 ? Encryption.EncryptPasswordDES(this.userName, this.password, this.serverSeed, this.clientSeed) : Encryption.EncryptPasswordSHA1(this.userName, this.password, this.serverSeed, this.clientSeed);

            outputStream.WriteByte(2); // Client attributes (2: return job information)
            outputStream.WriteByte(0); // Server attributes
            outputStream.WriteShort(ServerIDRemoteCommand); // Server ID
            outputStream.WriteInt(0); // CS instance
            outputStream.WriteInt(0); // Correlation ID
            outputStream.WriteShort(2);  // Template length
            outputStream.WriteShort(0x7002);  // ReqReP ID
            outputStream.WriteByte((byte)(this.passwordLevel < 2 ? 1 : 3)); // Password encryption type
            outputStream.WriteByte(1); // Send reply
            outputStream.WriteInt(6 + (uint)encryptedPassword.Length);  // Password LL
            outputStream.WriteShort(0x1105);  // Password CP. 0x1115 is other. 
            outputStream.Write(encryptedPassword, 0, encryptedPassword.Length); // Password
            outputStream.WriteInt(16); // User ID LL
            outputStream.WriteShort(0x1104); // User ID CP
            outputStream.Write(userID, 0, userID.Length); // UserID

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
             *  20                  Result code         4
             *  24                  (Dynamic fields)    see below
             *  -----------------------------------------------------------
             *  Dynamic fields (Offset is dynamic)
             *  -----------------------------------------------------------
             *  0                   Field length        4
             *  4                   Field code          2
             *  6                   Field data          (Field length - 6)
             */

            // Read fixed header
            inputStream.Position = 0;
            uint responseLength = inputStream.ReadInt();
            if (responseLength < 20)
                throw new System.InvalidOperationException("Authentication failed. Bad response length.");

            inputStream.Position += 16;

            uint resultCode = inputStream.ReadInt();
            if (resultCode != 0)
            {
                if ((resultCode & 0xFFFF0000) == 0x00010000)
                    throw new System.InvalidOperationException("Authentication failed. Error on request data.");
                if ((resultCode & 0xFFFF0000) == 0x00040000)
                    throw new System.InvalidOperationException("Authentication failed. General security error, function not performed.");
                if ((resultCode & 0xFFFF0000) == 0x00060000)
                    throw new System.InvalidOperationException("Authentication failed. Authentication token error.");
                switch (resultCode)
                {
                    case 0x00020001:
                        throw new System.InvalidOperationException("Authentication failed. User ID unknown.");
                    case 0x00020002:
                        throw new System.InvalidOperationException("Authentication failed. User ID locked.");
                    case 0x00020003:
                        throw new System.InvalidOperationException("Authentication failed. User ID doesn't match the authentication token.");
                    case 0x0003000B:
                        throw new System.InvalidOperationException("Authentication failed. Password incorrect.");
                    case 0x0003000C:
                        throw new System.InvalidOperationException("Authentication failed. Password incorrect. User profile will be revoked on next invalid password or passphrase.");
                    case 0x0003000D:
                        throw new System.InvalidOperationException("Authentication failed. Password is expired.");
                    case 0x0003000E:
                        throw new System.InvalidOperationException("Authentication failed. Pre-V2R2 encrypted password.");
                    case 0x00030010:
                        throw new System.InvalidOperationException("Authentication failed. Password is *NONE.");
                    default:
                        throw new System.InvalidOperationException("Authentication failed. Return code 0x" + resultCode.ToString("X8"));
                }
            }

            while (inputStream.Position < responseLength)
            {
                uint dynamicFieldLength = inputStream.ReadInt();
                ushort dynamicFieldCode = inputStream.ReadShort();
                byte[] dynamicFieldData = new byte[dynamicFieldLength - 6];
                inputStream.Read(dynamicFieldData, 0, (int)dynamicFieldLength - 6);

                switch (dynamicFieldCode)
                {
                    case 0x111F:    // Server Version
                        this.jobName = Converters.EbcdicToAsciiString(dynamicFieldData, 4);
                        break;
                    default:
                        break;
                }
            }

            Debug.WriteLine("User authenticated to remote command server.");
        }
    }
}
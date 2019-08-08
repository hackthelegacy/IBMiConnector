//-----------------------------------------------------------------------
// <copyright file="IBMiConnector.cs" company="Bart Kulach">
// Copyright (C) 2018-2019 Bart Kulach
// This file, IBMiConnector.cs, is part of the IBMiConnector package.
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
    using System.Diagnostics;

    /// <summary>
    /// Class IBMiConnector allows for direct interfacing with IBM Power i Systems,
    /// aiming for delivering similar functionality to IBM's public connectivity libraries for Java.
    /// </summary>
    public partial class IBMiConnector
    {
        //-----------------------------------------------------------------------
        // Constants
        //-----------------------------------------------------------------------

        /// <summary>TCP port for Server Mapper</summary>
        private const int TcpPortServerMapper = 449;

        /// <summary>TCP port for License Management (non-SSL)</summary>
        private const int TcpPortLicenseManagement = 8470;

        /// <summary>TCP port for License Management (SSL)</summary>
        private const int TcpPortLicenseManagementSSL = 9470;

        /// <summary>TCP port for Database Access (as-database) (non-SSL)</summary>
        private const int TcpPortDatabaseAccess = 8471;

        /// <summary>TCP port for Database Access (as-database) (SSL)</summary>
        private const int TcpPortDatabaseAccessSSL = 9471;

        /// <summary>TCP port for Data Queues (as-dtaq) (non-SSL)</summary>
        private const int TcpPortDataQueues = 8472;

        /// <summary>TCP port for Data Queues (as-dtaq) (SSL)</summary>
        private const int TcpPortDataQueuesSSL = 9472;

        /// <summary>TCP port for IFS Access (as-file) (non-SSL)</summary>
        private const int TcpPortIFSAccess = 8473;

        /// <summary>TCP port for IFS Access (as-file) (SSL)</summary>
        private const int TcpPortIFSAccessSSL = 9473;

        /// <summary>TCP port for Network Printers (as-netprt) (non-SSL)</summary>
        private const int TcpPortNetworkPrinter = 8474;

        /// <summary>TCP port for Network Printers (as-netprt) (SSL)</summary>
        private const int TcpPortNetworkPrinterSSL = 9474;

        /// <summary>TCP port for Remote Command (as-rmtcmd) (non-SSL)</summary>
        private const int TcpPortRemoteCommand = 8475;

        /// <summary>TCP port for Remote Command (as-rmtcmd) (SSL)</summary>
        private const int TcpPortRemoteCommandSSL = 9475;

        /// <summary>TCP port for sign-on verification (as-signon) (non-SSL)</summary>
        private const int TcpPortSignonVerify = 8476;

        /// <summary>TCP port for sign-on verification (as-signon) (SSL)</summary>
        private const int TcpPortSignonVerifySSL = 9476;

        /// <summary>TCP port for Telnet (non-SSL)</summary>
        private const int TcpPortTelnet = 23;

        /// <summary>TCP port for Telnet (SSL)</summary>
        private const int TcpPortTelnetSSL = 992;

        /// <summary>TCP port for Service Tools (non-SSL)</summary>
        private const int TcpPortServiceTools = 3000;

        /// <summary>Server ID for Central Management (as-central)</summary>
        private const ushort ServerIDCentralManagement = 0xE000;

        /// <summary>Server ID for IFS Access (as-file)</summary>
        private const ushort ServerIDIFSAccess = 0xE002;

        /// <summary>Server ID for Network Printer (as-netprt)</summary>
        private const ushort ServerIDNetworkPrinter = 0xE003;

        /// <summary>Server ID for Database access (as-database, SQL)</summary>
        private const ushort ServerIDDatabaseAccessSQL = 0xE004;

        /// <summary>Server ID for Database access (as-database, NDB)</summary>
        private const ushort ServerIDDatabaseAccessNDB = 0xE005;

        /// <summary>Server ID for Database access (as-database, ROI)</summary>
        private const ushort ServerIDDatabaseAccessROI = 0xE006;

        /// <summary>Server ID for Data Queues (as-dtaq)</summary>
        private const ushort ServerIDDataQueues = 0xE007;

        /// <summary>Server ID for Remote Command (as-rmtcmd)</summary>
        private const ushort ServerIDRemoteCommand = 0xE008;

        /// <summary>Server ID for sign-on verification (as-signon)</summary>
        private const ushort ServerIDSignonVerify = 0xE009;

        //-----------------------------------------------------------------------
        // Class fields
        //-----------------------------------------------------------------------

        /// <summary>Holds the server's FQDN or IP address</summary>
        private string serverName;

        /// <summary>Holds the User name</summary>
        private string userName;

        /// <summary>Holds the User's password</summary>
        private string password;

        /// <summary>Holds the information on SSL usage</summary>
        private bool useSSL;

        /// <summary>Holds information about the use of self-signed SSL certificates</summary>
        private bool ignoreSelfSignedCertificates;

        /// <summary>Holds the Temporary Library name</summary>
        private string temporaryLibrary;

        /// <summary>Holds information about the Server Version</summary>
        private uint serverVersion = 0;

        /// <summary>Holds information about the Server Level</summary>
        private uint serverLevel = 0;

        /// <summary>Holds information about the Server's CCSID</summary>
        private uint serverCCSID = 037;

        /// <summary>Holds information about the Server's NLV</summary>
        private string serverNLV = "2924";

        /// <summary>Holds information about the Server's NLV</summary>
        private ushort serverDatastreamLevel = 0;

        /// <summary>Holds information about the Password Level</summary>
        private byte passwordLevel = 0;

        /// <summary>Holds information about the current Job Name</summary>
        private string jobName = string.Empty;

        //-----------------------------------------------------------------------

        /// <summary>Initializes a new instance of the <see cref="IBMiConnector"/> class.</summary>
        /// <param name="serverName">FQDN or IP address of the IBM i server</param>
        /// <param name="userName">User name</param>
        /// <param name="password">User's password</param>
        /// <param name="temporaryLibrary">Temporary library (default = QTEMP)</param>
        /// <param name="useSSL">If True, connection will be established with SSL.</param>
        /// <param name="ignoreSelfSignedCertificates">If True, SSL connection will be established even if with certificate errors (use with care!)</param>
        public IBMiConnector(string serverName, string userName, string password, string temporaryLibrary = "QTEMP", bool useSSL = false, bool ignoreSelfSignedCertificates = true)
        {
            this.serverName = serverName;
            this.userName = userName;
            this.password = password;
            this.useSSL = useSSL;
            this.ignoreSelfSignedCertificates = ignoreSelfSignedCertificates;
            this.temporaryLibrary = temporaryLibrary;
            Debug.WriteLine("An instance of IBMiConnector class for server " + this.serverName + " was created.");
        }

        /// <summary>Finalizes an instance of the <see cref="IBMiConnector"/> class.</summary>
        ~IBMiConnector()
        {
            this.Disconnect();
        }
    }
}

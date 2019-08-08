//-----------------------------------------------------------------------
// <copyright file="SocketConnector.cs" company="Bart Kulach">
// Copyright (C) 2018-2019 Bart Kulach
// This file, SocketConnector.cs, is part of the IBMiConnector package.
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
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;

    /// <summary>
    /// Class SocketConnector delivers socket connectivity to IBM i system, either with or without SSL.
    /// </summary>
    internal class SocketConnector
    {
        //-----------------------------------------------------------------------
        // Constants
        //-----------------------------------------------------------------------

        //-----------------------------------------------------------------------
        // Class fields
        //-----------------------------------------------------------------------

        /// <summary>Holds information about SSL usage</summary>
        private bool useSSL;

        /// <summary>Holds information about the used port number</summary>
        private int portNumber;

        /// <summary>Holds information about the used server</summary>
        private string serverName;

        /// <summary>Holds information about the use of self-signed SSL certificates</summary>
        private bool ignoreSelfSignedCertificates;

        /// <summary>Holds information about the TCP Client</summary>
        private TcpClient tcpClient = null;

        /// <summary>Holds information about the data stream</summary>
        private BufferedStream bufferedStream = null;

        //-----------------------------------------------------------------------

        /// <summary>Initializes a new instance of the <see cref="SocketConnector"/> class.</summary>
        /// <param name="serverName">FQDN or IP address of the IBM i server</param>
        /// <param name="portNumber">TCP port number</param>
        /// <param name="useSSL">If True, connection will be established with SSL.</param>
        /// <param name="ignoreSelfSignedCertificates">If True, SSL connection will be established even if with certificate errors (use with care!)</param>
        public SocketConnector(string serverName, int portNumber, bool useSSL, bool ignoreSelfSignedCertificates = true)
        {
            // Establish port connection
            this.tcpClient = new TcpClient(serverName, portNumber);
            Debug.WriteLine("Socket connection to " + serverName + " established on port " + portNumber);

            if (useSSL)
            {
                SslStream sslStream;

                sslStream = ignoreSelfSignedCertificates ? new SslStream(this.tcpClient.GetStream(), false, new RemoteCertificateValidationCallback(IgnoreServerCertificate), null) : new SslStream(this.tcpClient.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);

                sslStream.AuthenticateAsClient(serverName);

                this.bufferedStream = new BufferedStream(sslStream);
            }
            else
            {
                NetworkStream networkStream = this.tcpClient.GetStream();
                this.bufferedStream = new BufferedStream(networkStream);
            }

            // Set internal variables
            this.serverName = serverName;
            this.portNumber = portNumber;
            this.useSSL = useSSL;
            this.ignoreSelfSignedCertificates = ignoreSelfSignedCertificates;

            return;
        }

        /// <summary>Finalizes an instance of the <see cref="SocketConnector"/> class.</summary>
        ~SocketConnector()
        {
            this.Disconnect();
        }

        /// <summary>Closes the connection.</summary>
        public void Disconnect()
        {
            this.bufferedStream?.Close();
            this.tcpClient?.Close();
        }

        /// <summary>Sends data over an open stream.</summary>
        /// <param name="outputData">Data to be sent</param>
        public void Write(byte[] outputData)
        {
            if (this.bufferedStream.CanWrite)
            {
                byte[] requestLength = Converters.UInt32ToBigEndian((uint)outputData.Length + 4);
                this.bufferedStream.Write(requestLength, 0, requestLength.Length);
                this.bufferedStream.Write(outputData, 0, outputData.Length);
                this.bufferedStream.Flush();
            }
        }

        /// <summary>Receives data from an open stream.</summary>
        /// <returns>Retrieved data</returns>
        public byte[] Read()
        {
            byte[] responseLength = new byte[4];

            using (BigEndianMemoryStream readStream = new BigEndianMemoryStream())
            {
                if (!this.bufferedStream.CanRead)
                    return null;

                this.bufferedStream.Read(responseLength, 0, 4);
                readStream.Write(responseLength, 0, 4);
                Debug.WriteLine("Packet length: " + BitConverter.ToString(responseLength));
                long bytesToRead = Converters.BigEndianToUInt32(responseLength);
                if (bytesToRead == 0x00000000 || bytesToRead == 0x40404040)
                    return null;

                bytesToRead -= 4;
                while (bytesToRead > 0)
                {
                    byte[] buffer = new byte[(long)byte.MaxValue < bytesToRead ? byte.MaxValue : (int)bytesToRead];
                    if (!this.bufferedStream.CanRead)
                        Thread.Sleep(100);
                    this.bufferedStream.Read(buffer, 0, buffer.Length);
                    readStream.Write(buffer, 0, buffer.Length);
                    bytesToRead -= buffer.Length;
                }
                return readStream.ToArray();
            }
        }

        //-----------------------------------------------------------------------
        // Private methods
        //-----------------------------------------------------------------------

        /// <summary>Validates the SSL certificate.</summary>
        /// <param name="sender">Input data</param>
        /// <param name="certificate">Received certificate</param>
        /// <param name="chain">Received certificate chain</param>
        /// <param name="sslPolicyErrors">Policy errors encountered</param>
        /// <returns>If True, certificate validation was positive.</returns>
        private static bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            // Check if policy errors occured
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Debug.WriteLine("Certificate error: " + sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }

        /// <summary>Validates (ignores) the SSL certificate.</summary>
        /// <param name="sender">Input data</param>
        /// <param name="certificate">Received certificate</param>
        /// <param name="chain">Received certificate chain</param>
        /// <param name="sslPolicyErrors">Policy errors encountered</param>
        /// <returns>If True, certificate validation was positive.</returns>
        private static bool IgnoreServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            Debug.WriteLine("Accepting self signed certificates.");

            // Check if policy errors occured
            if (sslPolicyErrors != SslPolicyErrors.None)
                Debug.WriteLine("Ignoring certificate errors: " + sslPolicyErrors);

            return true;
        }
    }
}

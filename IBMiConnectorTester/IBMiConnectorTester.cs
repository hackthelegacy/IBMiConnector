//-----------------------------------------------------------------------
// <copyright file="IBMiConnectorTester.cs" company="Bart Kulach">
// Copyright (C) 2018-2019 Bart Kulach
// This file, IBMiConnectorTester.cs, is part of the IBMiConnector package.
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

namespace IBMiConnectorTester
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Class IBMiConnectorTester delivers testing functionality for the IBMiConnector library.
    /// </summary>
    public class IBMiConnectorTester
    {
        /// <summary>Main method</summary>
        /// <param name="args">Command line parameters</param>
        public static void Main(string[] args)
        {
            IBMiConnector.IBMiConnector ibmIConnector = new IBMiConnector.IBMiConnector("SERVER", "QSECOFR", "PASSWORD", "QTEMP", true);
            ibmIConnector.Connect();

            //Example 1: Getting password hash (LM hash - if QPWDLVL is < 3)
            Debug.WriteLine("User's password LM hash is : " + ibmIConnector.GetEncryptedPassword("QSECOFR", IBMiConnector.IBMiConnector.PASSWORD_HASH_LMHASH));

            //Example 2: Getting the full list of users
            string[] users = ibmIConnector.GetUsersList();
            Debug.WriteLine("List of users:");
            foreach (string user in users)
                Debug.WriteLine(user);
        }


    }
}

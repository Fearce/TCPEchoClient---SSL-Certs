/*
 * TCPEchoClient
 *
 * Author Michael Claudius, ZIBAT Computer Scienc
 * Version 1.0. 2014.02.10
 * Copyright 2014 by Michael Claudius
 * Revised 2014.09.01, 2016.09.14
 * All rights reserved
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace TCPEchoClient
{
    class TCPEchoClient
    {
        static void Main(string[] args)
        {
            ////Console.ReadLine();
            //TcpClient clientSocket = new TcpClient("127.0.0.1", 6789);
            //Console.WriteLine("Client ready");

            //Stream ns = clientSocket.GetStream();  //provides a Stream
            //StreamReader sr = new StreamReader(ns);
            //StreamWriter sw = new StreamWriter(ns);
            //sw.AutoFlush = true; // enable automatic flushing

            //string message = Console.ReadLine();
            //sw.WriteLine(message);
            //string serverAnswer = sr.ReadLine();

            //Console.WriteLine("Server: " + serverAnswer);

            //Console.WriteLine("No more from server. Press Enter");
            //Console.ReadLine();

            //ns.Close();

            //clientSocket.Close();
            Console.WriteLine("Input client name");
            string clientName = Console.ReadLine();
            TCPClient1 client = new TCPClient1(clientName);
            client.Main();

        }

    }

}

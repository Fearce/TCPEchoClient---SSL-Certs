using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TCPEchoClient
{
    class TCPClient1
    {
        private string ClientName;

        public async void Main()
        {
           
           Setup();

        }

        public TCPClient1(string clientName)
        {
            ClientName = clientName;
        }

        public void Setup()
        {
            //Console.ReadLine();
            TcpClient clientSocket = new TcpClient("127.0.0.1", 6789);
            Console.WriteLine(ClientName + " ready");

            //SSL stuff below
            string serverCertificateFile = "c:/Certificates/ServerSSL.cer";
            bool clientCertificateRequired = true;
            bool checkCertificateRevocation = false;
            SslProtocols enabledSSLProtocols = SslProtocols.Tls;
            X509Certificate serverCertificate = new X509Certificate(serverCertificateFile, "secret");

            Stream unsecureStream = clientSocket.GetStream();

            bool leaveInnerStreamOpen = false;
            string certificateServerName = "FakeServerName";

            //bool CertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            //{
            //    if (sslPolicyErrors != SslPolicyErrors.None)
            //    {
            //        Console.WriteLine("SSL Certificate Validation Error!");
            //        Console.WriteLine(sslPolicyErrors.ToString());
            //        return false;
            //    }
            //    else
            //        return true;
            //}

            bool CertificateValidationCallBack(
                object sender,
                System.Security.Cryptography.X509Certificates.X509Certificate certificate,
                System.Security.Cryptography.X509Certificates.X509Chain chain,
                System.Net.Security.SslPolicyErrors sslPolicyErrors)
            {
                // If the certificate is a valid, signed certificate, return true.
                if (sslPolicyErrors == System.Net.Security.SslPolicyErrors.None)
                {
                    return true;
                }

                // If there are errors in the certificate chain, look at each error to determine the cause.
                if ((sslPolicyErrors & System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors) != 0)
                {
                    if (chain != null && chain.ChainStatus != null)
                    {
                        foreach (System.Security.Cryptography.X509Certificates.X509ChainStatus status in chain.ChainStatus)
                        {
                            if ((certificate.Subject == certificate.Issuer) &&
                                (status.Status == System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.UntrustedRoot))
                            {
                                // Self-signed certificates with an untrusted root are valid. 
                                continue;
                            }
                            else
                            {
                                if (status.Status != System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.NoError)
                                {
                                    // If there are any other errors in the certificate chain, the certificate is invalid,
                                    // so the method returns false.
                                    return false;
                                }
                            }
                        }
                    }

                    // When processing reaches this line, the only errors in the certificate chain are 
                    // untrusted root errors for self-signed certificates. These certificates are valid
                    // for default Exchange server installations, so return true.
                    return true;
                }
                else
                {
                    // In all other cases, return false.
                    return false;
                }
            }



            X509Certificate CertificateSelectionCallback(object sender,
                string targetHost,
                X509CertificateCollection localCertificates,
                X509Certificate remoteCertificate,
                string[] acceptableIssuers)
            {
                return serverCertificate;
            }

           // SslStream sslStream = new SslStream(unsecureStream, leaveInnerStreamOpen);
            SslStream sslStream = new SslStream(unsecureStream, leaveInnerStreamOpen,
                CertificateValidationCallBack, //remote
                CertificateSelectionCallback); //local

            sslStream.AuthenticateAsClient(certificateServerName); // help The server mode SSL must use a certificate with the associated private key.



            Stream ns = clientSocket.GetStream();  //provides a Stream - old without ssl

            

            StreamReader sr = new StreamReader(sslStream);
            StreamWriter sw = new StreamWriter(sslStream);
            sw.AutoFlush = true; // enable automatic flushing
            Task.Run((() => //Printer response på en seperat tråd så konsollen stadig er klar til Msg();
            {
                while (true)
                {
                    PrintResponse(sr, sw);
                }
            }));
            while (true)
            {
                Msg(sr, sw, clientSocket);
            }
            //Stop(ns, clientSocket);

        }

        public async void PrintResponse(StreamReader sr, StreamWriter sw)
        {
            string serverAnswer = sr.ReadLine();
            Console.WriteLine("Response: " + serverAnswer);
        }

        public void Msg(StreamReader sr, StreamWriter sw, TcpClient client)
        {
            string message = Console.ReadLine(); //Sends original message
            sw.WriteLine(ClientName + " : " + message); //Writes message to server

        }

        public void Stop(Stream ns, TcpClient clientSocket)
        {
            Console.WriteLine("No more from server. Press Enter");
            Console.ReadLine();

            ns.Close();

            clientSocket.Close();
        }

    }
}

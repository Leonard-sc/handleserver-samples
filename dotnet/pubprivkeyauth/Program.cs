using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace pubprivkeyauth
{
    class Program
    {
        static void Main(string[] args)
        {
            System.Net.ServicePointManager.ServerCertificateValidationCallback += RemoteCertificateValidationCallback;

            Task.Factory.StartNew(() =>
            {
                NoSession noSession = new NoSession();
                noSession.DoHandleWork().Wait();
            }).Wait();

            Task.Factory.StartNew(() =>
            {
                Session session = new Session();
                session.DoHandleWork().Wait();
            }).Wait();
        }

        public static bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }
}

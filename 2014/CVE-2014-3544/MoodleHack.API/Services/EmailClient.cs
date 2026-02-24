using System;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace MoodleHack.API.Services
{
    public class EmailClient : IDisposable
    {
        private readonly SmtpClient _smtpClient;
        private readonly EmailConfiguration _configuration;

        public EmailClient(IOptions<EmailConfiguration> config)
        {
            _configuration = config.Value;

            _smtpClient = new SmtpClient
            {
                Host = _configuration.Host,
                Port = _configuration.Port,
                EnableSsl = true,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(_configuration.Email, _configuration.Password)
            };
        }
        public Task SendMessage(string toEmail, string toDisplayName, string message)
        {
            try
            {
                var mail = new MailMessage
                {
                    From = _configuration.From,
                    Subject = _configuration.Subject,
                    SubjectEncoding = Encoding.UTF8,
                    Body = message,
                    IsBodyHtml = true,
                    BodyEncoding = Encoding.UTF8
                };
                
                var to = new MailAddress(toEmail, toDisplayName);
                mail.To.Add(to);

                _smtpClient.Send(mail);

                return Task.CompletedTask;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void Dispose()
        {
            _smtpClient?.Dispose();
        }
    }
}
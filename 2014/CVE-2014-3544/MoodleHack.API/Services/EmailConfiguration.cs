using System.Net.Mail;

namespace MoodleHack.API.Services
{
    public class EmailConfiguration
    {
        public EmailConfiguration()
        { }

        public EmailConfiguration(string host, 
            string email, 
            string password, 
            string displayNameEmail,
            string subject)
        {
            Host = host;
            Email = email;
            Password = password;
            DisplayNameEmail = displayNameEmail;
            Subject = subject;
        }
        public string Host { get; set; }
        public int Port { get; set; } = 587;
        public string Email { get; set; }
        public string Password { get; set; }
        public string DisplayNameEmail { get; set; }
        public string Subject { get; set; }
        public MailAddress From => new(Email, DisplayNameEmail);
    }
}
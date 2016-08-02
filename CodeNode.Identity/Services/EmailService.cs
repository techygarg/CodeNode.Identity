using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using CodeNode.Identity.Utilities;
using Microsoft.AspNet.Identity;

namespace CodeNode.Identity.Services
{
    internal class EmailService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            return SendEmail(message);
        }

        private static Task SendEmail(IdentityMessage mail)
        {
            var smtpClient = new SmtpClient(AppSettingsValueProvider.Smtp, AppSettingsValueProvider.SmtpPort)
            {
                Credentials =
                    new NetworkCredential(AppSettingsValueProvider.SmtpSender,
                        AppSettingsValueProvider.SmtpSenderPassword),
                UseDefaultCredentials = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                EnableSsl = AppSettingsValueProvider.EnableSsl
            };

            var message = new MailMessage
            {
                From = new MailAddress(AppSettingsValueProvider.SmtpSender, AppSettingsValueProvider.SenderDisplayName)
            };

            message.To.Add(new MailAddress(mail.Destination));
            message.Subject = mail.Subject;
            message.Body = mail.Body;
            message.IsBodyHtml = AppSettingsValueProvider.IsEmailBodyHtml;
            smtpClient.Send(message);
            return Task.FromResult(0);
        }
    }
}
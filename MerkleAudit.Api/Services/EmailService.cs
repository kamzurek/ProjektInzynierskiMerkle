using MailKit.Net.Smtp;
using MimeKit;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;

namespace MerkleAudit.Api.Services
{
    public class EmailService
    {
        public async Task SendAlertEmailAsync(string alertMessage)
        {
            var email = new MimeMessage();

            // Od kogo (fikcyjny adres naszego systemu)
            email.From.Add(MailboxAddress.Parse("watchdog@merkleaudit.pl"));

            // Do kogo (tu wpisz swój prawdziwy adres e-mail, żeby odebrać powiadomienie!)
            email.To.Add(MailboxAddress.Parse("twoj.prawdziwy.mail@gmail.com"));

            email.Subject = "KRYTYCZNY ALARM: Naruszenie integralności bazy danych!";

            // Budujemy ładną treść w HTML
            email.Body = new TextPart(MimeKit.Text.TextFormat.Html)
            {
                Text = $@"
                    <div style='font-family: Arial, sans-serif; color: #333;'>
                        <h2 style='color: #d9534f;'>Wykryto naruszenie bezpieczeństwa!</h2>
                        <p>Nasz zautomatyzowany Strażnik Systemu wykrył nieautoryzowaną modyfikację w logach transakcji.</p>
                        <div style='background-color: #f9f2f4; color: #c7254e; padding: 15px; border-left: 5px solid #d9534f; margin: 20px 0;'>
                            <strong>Szczegóły logu systemowego:</strong><br/>
                            <p style='font-family: monospace;'>{alertMessage}</p>
                        </div>
                        <p>Zalecana jest natychmiastowa weryfikacja bazy danych i zablokowanie dostępu do serwera.</p>
                    </div>"
            };

            // Wysyłamy maila używając darmowego serwera testowego Mailtrap (lub dowolnego SMTP)
            using var smtp = new SmtpClient();

            try
            {
                // UWAGA: Tutaj wpiszemy dane testowe, o których za chwilę Ci opowiem
                await smtp.ConnectAsync("sandbox.smtp.mailtrap.io", 2525, MailKit.Security.SecureSocketOptions.StartTls);

                // Zmień te dane na swoje z Mailtrapa!
                await smtp.AuthenticateAsync("c6fb26ab7c31fa", "81147a57356c32");

                await smtp.SendAsync(email);
            }
            finally
            {
                await smtp.DisconnectAsync(true);
            }
        }
    }
}
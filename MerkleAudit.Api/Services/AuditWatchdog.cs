using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;
using MerkleAudit.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace MerkleAudit.Api.Services
{
    // Dziedziczenie po BackgroundService sprawia, że ta klasa działa w tle,
    // całkowicie niezależnie od tego, czy ktoś "klika" w aplikację.
    public class AuditWatchdog : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<AuditWatchdog> _logger;

        public AuditWatchdog(IServiceProvider serviceProvider, ILogger<AuditWatchdog> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        // Ta metoda to serce naszego skanera
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogWarning(">>> [STRAŻNIK] Rozpoczęto patrol systemu. Wypatruję włamań...");

            // Pętla kręci się w nieskończoność, dopóki nie wyłączymy serwera
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    // W procesach w tle musimy sami otworzyć "połączenie" (Scope) do bazy
                    using (var scope = _serviceProvider.CreateScope())
                    {
                        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                        var cryptoService = scope.ServiceProvider.GetRequiredService<CryptoService>();

                        var logs = await dbContext.AuditLogs.ToListAsync(stoppingToken);
                        bool isCorrupted = false;

                        // Skanujemy każdy wpis w bazie linijka po linijce
                        foreach (var log in logs)
                        {
                            // Wyliczamy hash na nowo na podstawie tego, co JEST w bazie
                            string expectedHash = cryptoService.CalculateHashForLog(log);

                            // Porównujemy go z "plombą" zapisaną w bazie
                            if (log.Hash != expectedHash)
                            {
                                // ALARM W KONSOLI!
                                _logger.LogCritical($">>> [ALARM WŁAMANIA!] Zmodyfikowano wpis ID: {log.Id} z pominięciem serwera!");
                                _logger.LogCritical($"    Oczekiwano: {expectedHash}");
                                _logger.LogCritical($"    W bazie:    {log.Hash}");
                                isCorrupted = true;

                                // WYSYŁAMY MAILA!
                                // Ponieważ jesteśmy w pętli działającej w tle, "wyciągamy" serwis pocztowy z naszego Scope'a
                                var emailService = scope.ServiceProvider.GetRequiredService<EmailService>();

                                string emailMessage = $"Zmodyfikowano wpis ID: {log.Id}.<br/>Oczekiwany Hash: {expectedHash}<br/>Hash w bazie: {log.Hash}";

                                // Dodajemy await, żeby poczekać na wysłanie maila
                                await emailService.SendAlertEmailAsync(emailMessage);
                            }
                        }

                        if (!isCorrupted && logs.Count > 0)
                        {
                            _logger.LogInformation($">>> [Strażnik] Baza bezpieczna. Przeskanowano wpisów: {logs.Count}.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($">>> [Strażnik] Błąd podczas skanowania: {ex.Message}");
                }

                // Strażnik idzie spać na 15 sekund (do testów), potem zrobi to np. na 60
                await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
            }
        }
    }
}
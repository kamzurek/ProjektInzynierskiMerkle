/**
 * ============================================================================
 * Politechnika Śląska
 * Wydział Inżynierii Materiałowej i Cyfryzacji Przemysłu
 * Kierunek: Informatyka Przemysłowa
 * * PROJEKT INŻYNIERSKI
 * Tytuł: "Kryptograficznie weryfikowalny dziennik audytu operacji w systemach webowych"
 * * Autor: Kamil Żurek
 * Nr albumu: 305428
 * Prowadzący pracę: dr inż. Łukasz Maliński
 * Rok akademicki: 2025/2026
 * ============================================================================
 */


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
                        var emailService = scope.ServiceProvider.GetRequiredService<EmailService>();

                        // DODANO: Pobieramy globalny stan
                        var appState = scope.ServiceProvider.GetRequiredService<GlobalAppState>();

                        // Jeśli system już jest w kwarantannie, Watchdog nie musi ciągle wysyłać maili
                        if (appState.IsQuarantineActive)
                        {
                            await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
                            continue;
                        }

                        var logs = await dbContext.AuditLogs.OrderBy(l => l.Id).ToListAsync(stoppingToken);
                        bool isCorrupted = false;

                        // Używamy pętli FOR, żeby mieć dostęp do indeksu [i] oraz wpisu poprzedniego [i-1]
                        for (int i = 0; i < logs.Count; i++)
                        {
                            var log = logs[i];
                            string expectedHash = cryptoService.CalculateHashForLog(log);

                            // --- 1. SPRAWDZANIE PLOMBY (Twoja dotychczasowa logika) ---
                            if (log.Hash != expectedHash)
                            {
                                _logger.LogCritical($">>> [ALARM WŁAMANIA!] Zmodyfikowano zawartość wpisu ID: {log.Id}!");
                                isCorrupted = true;

                                string emailMessage = $"<strong>Naruszenie danych!</strong><br/>Zmodyfikowano wpis ID: {log.Id}.<br/>Oczekiwany Hash: {expectedHash}<br/>Hash w bazie: {log.Hash}";
                                await emailService.SendAlertEmailAsync(emailMessage);

                                appState.IsQuarantineActive = true;
                                appState.QuarantineReason = $"Zablokowano z powodu wpisu ID: {log.Id}";
                            }

                            // --- 2. SPRAWDZANIE ŁAŃCUCHA (Nasza nowa ochrona przed inteligentnym atakiem) ---
                            if (i > 0 && log.PreviousHash != logs[i - 1].Hash)
                            {
                                _logger.LogCritical($">>> [ZERWANY ŁAŃCUCH!] Wpis ID: {log.Id} stracił kryptograficzne powiązanie z wpisem ID: {logs[i - 1].Id}!");
                                isCorrupted = true;

                                string emailMessage = $"<strong>Zerwanie łańcucha bloków!</strong><br/>Wpis ID: {log.Id} ma błędny PreviousHash. Ktoś podmienił historyczną transakcję ID: {logs[i - 1].Id} i wyliczył nowy hash!";
                                await emailService.SendAlertEmailAsync(emailMessage);

                                appState.IsQuarantineActive = true;
                                appState.QuarantineReason = $"Zablokowano z powodu wpisu ID: {log.Id}";
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
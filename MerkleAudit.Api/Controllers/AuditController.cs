using MerkleAudit.Api.Data;
using MerkleAudit.Api.Models;
using MerkleAudit.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;

namespace MerkleAudit.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    // Celowo brak [Authorize] tutaj, aby precyzyjnie zarządzać dostępem wewnątrz klasy
    public class AuditController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly MerkleTreeBuilder _treeBuilder;
        private readonly CryptoService _cryptoService;
        private readonly GlobalAppState _appState;

        public AuditController(AppDbContext context, MerkleTreeBuilder treeBuilder, CryptoService cryptoService, GlobalAppState appState)
        {
            _context = context;
            _treeBuilder = treeBuilder;
            _cryptoService = cryptoService;
            _appState = appState;
        }

        // --- FUNKCJA POMOCNICZA: Weryfikacja Stateful (czy User z tokenu nadal istnieje w bazie) ---
        private async Task<bool> IsSessionValid()
        {
            var loggedInUser = User.Identity?.Name;
            if (string.IsNullOrEmpty(loggedInUser)) return false;

            // Fizycznie sprawdzamy, czy w wyczyszczonej bazie nadal istnieje ten login
            return await _context.Users.AnyAsync(u => u.Username == loggedInUser);
        }
        // -----------------------------------------------------------------------------------------

        // 1. Wgląd do historii przelewów - DOPASOWANY DO ROLI
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> GetAllLogs()
        {
            // BLOKADA SESJI
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła lub baza została zresetowana.");

            var loggedInUser = User.Identity?.Name;

            // Jeśli zalogowany to Administrator -> widzi pełny rejestr systemowy
            if (User.IsInRole("Admin"))
            {
                var allLogs = await _context.AuditLogs.ToListAsync();
                return Ok(allLogs);
            }

            // Jeśli to zwykły użytkownik -> filtrujemy bazę, zwracając wyłącznie jego przelewy
            var userTransfers = await _context.AuditLogs
                .Where(l => l.Sender == loggedInUser)
                .ToListAsync();

            return Ok(userTransfers);
        }

        // 2. Dodanie starego typu logu ręcznie - TYLKO DLA ADMINA
        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AddLog([FromBody] AuditLog newLog)
        {
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła.");

            _context.AuditLogs.Add(newLog);
            await _context.SaveChangesAsync();

            newLog.Hash = _cryptoService.CalculateHashForLog(newLog);
            await _context.SaveChangesAsync();

            return Ok(newLog);
        }

        // 3. Pobieranie dowodów kryptograficznych - TYLKO DLA ADMINA
        [HttpGet("root")]
        [Authorize]
        public async Task<IActionResult> GetMerkleRoot()
        {
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła.");

            var logs = await _context.AuditLogs.ToListAsync();
            var root = _treeBuilder.BuildRoot(logs);

            if (string.IsNullOrEmpty(root))
            {
                return Ok(new { message = "Drzewo jest puste - brak logów" });
            }

            var digitalSignature = _cryptoService.SignData(root);
            var publicKey = _cryptoService.GetPublicKey();

            return Ok(new
            {
                currentRoot = root,
                serverSignature = digitalSignature,
                publicKey = publicKey
            });
        }

        // 4. NOWY PRZELEW: Dostępny DLA KAŻDEGO zalogowanego (Admin oraz User)
        [HttpPost("transfer")]
        [Authorize]
        public async Task<IActionResult> MakeTransfer(TransferDto request)
        {

            if (_appState.IsQuarantineActive)
            {
                return StatusCode(503, new { message = "SYSTEM ZABLOKOWANY (KWARANTANNA)", reason = _appState.QuarantineReason });
            }

            // BLOKADA SESJI
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła lub baza została zresetowana.");

            var loggedInUser = User.Identity?.Name;

            // Pobieramy IP i UserAgent
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown IP";
            var userAgent = Request.Headers["User-Agent"].ToString();
            if (string.IsNullOrEmpty(userAgent)) userAgent = "Unknown Device";

            var lastLog = await _context.AuditLogs.OrderByDescending(l => l.Id).FirstOrDefaultAsync();
            string previousHash = lastLog?.Hash ?? new string('0', 64);

            var newLog = new AuditLog
            {
                Sender = loggedInUser,
                Receiver = request.Receiver,
                Amount = request.Amount,
                PreviousHash = previousHash,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                Hash = "pending..."
            };

            _context.AuditLogs.Add(newLog);
            await _context.SaveChangesAsync();

            newLog.Hash = _cryptoService.CalculateHashForLog(newLog);

            await _context.SaveChangesAsync();

            return Ok(newLog);
        }

        // NOWOŚĆ: Pobieranie Dowodu Merkle
        [HttpGet("proof/{id}")]
        [Authorize]
        public async Task<IActionResult> GetMerkleProof(int id)
        {
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła.");

            var logTarget = await _context.AuditLogs.FindAsync(id);
            if (logTarget == null) return NotFound("Brak transakcji o takim ID.");

            // --- 🚨 ZABEZPIECZENIE 1: Weryfikacja Zawartości (Pudełko vs Plomba) ---
            var actualCalculatedHash = _cryptoService.CalculateHashForLog(logTarget);
            if (actualCalculatedHash != logTarget.Hash)
            {
                return BadRequest($"🚨 KRYTYCZNY BŁĄD INTEGRALNOŚCI!\nDane przelewu ID {id} zostały zmanipulowane w bazie.\nZapisana plomba nie zgadza się z aktualną kwotą/odbiorcą!");
            }

            var allLogs = await _context.AuditLogs.OrderBy(l => l.Id).ToListAsync();

            // --- 🚨 ZABEZPIECZENIE 2: Weryfikacja Łańcucha (Chronologia) ---
            for (int i = 1; i < allLogs.Count; i++)
            {
                if (allLogs[i].PreviousHash != allLogs[i - 1].Hash)
                {
                    return BadRequest($"🚨 ZERWANY ŁAŃCUCH BLOKÓW!\nWpis ID {allLogs[i].Id} posiada błędny PreviousHash. Ktoś podmienił historyczną transakcję ID {allLogs[i - 1].Id}!");
                }
            }

            var proof = _treeBuilder.GetProof(allLogs, logTarget.Hash);
            if (proof == null) return BadRequest("Nie udało się wygenerować dowodu kryptograficznego.");

            return Ok(new
            {
                LogId = id,
                TargetHash = logTarget.Hash,
                Proof = proof
            });
        }

        // 5. SYMULACJA ATAKU
        [HttpPost("simulate-attack/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> SimulateAttack(int id, [FromQuery] bool recalculateHash = false)
        {
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła.");

            var logToHack = await _context.AuditLogs.FindAsync(id);
            if (logToHack == null) return NotFound($"Brak transakcji o ID {id} w bazie!");

            // Zmieniamy kwotę (atak na dane)
            logToHack.Amount += 999999;

            if (recalculateHash)
            {
                // ATAK INTELIGENTNY: Haker zmienia dane i sam przelicza nowy hash.
                // Oszuka plombę, ale zerwie łańcuch (PreviousHash) dla kolejnego bloku!
                logToHack.Hash = _cryptoService.CalculateHashForLog(logToHack);
            }
            // Jeśli recalculateHash == false, to jest to ZWYKŁY ATAK: hash w bazie zostaje stary, a dane są nowe (plomba pęka).

            await _context.SaveChangesAsync();

            string attackType = recalculateHash ? "Inteligentny (Zerwanie Łańcucha)" : "Zwykły (Złamanie Plomby)";
            return Ok(new { message = $"Włamanie udane! Typ ataku: {attackType}. Kwota przelewu ID {logToHack.Id} została zmanipulowana. Watchdog powinien wkrótce zareagować." });
        }

        // 6. STATUS SERWERA I WATCHDOGA (Dla nowej zakładki w React)
        [HttpGet("status")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetServerStatus()
        {
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła.");

            return Ok(new
            {
                isQuarantineActive = _appState.IsQuarantineActive,
                quarantineReason = _appState.QuarantineReason,
                serverTime = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
                watchdogStatus = "Aktywny (Skanowanie w tle z częstotliwością 15s)"
            });
        }

        [HttpPost("reset-quarantine")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> ResetQuarantine()
        {
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła.");

            _appState.IsQuarantineActive = false;
            _appState.QuarantineReason = string.Empty;

            return Ok(new { message = "Kwarantanna została pomyślnie zdjęta. System wznawia normalną pracę." });
        }

        // 8. COFNIĘCIE ATAKU I NAPRAWA BAZY (Tylko na potrzeby prezentacji!)
        [HttpPost("revert-attack/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> RevertAttack(int id)
        {
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła.");

            var logToFix = await _context.AuditLogs.FindAsync(id);
            if (logToFix == null) return NotFound($"Brak transakcji o ID {id} w bazie!");

            // 1. Cofamy zmanipulowaną kwotę (odejmujemy to, co haker dodał)
            logToFix.Amount -= 999999;

            // 2. Przeliczamy ponownie prawidłowy hash (plomba wraca do normy)
            logToFix.Hash = _cryptoService.CalculateHashForLog(logToFix);
            await _context.SaveChangesAsync();

            // 3. Automatycznie zdejmujemy kwarantannę, bo baza jest już czysta
            _appState.IsQuarantineActive = false;
            _appState.QuarantineReason = string.Empty;

            return Ok(new { message = $"Baza danych naprawiona! Wpis ID {id} wrócił do oryginału, a kwarantanna została zdjęta." });
        }

        // 9. HARD RESET BAZY DANYCH (Tylko na potrzeby prezentacji)
        [HttpDelete("reset-database")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> ResetDatabase()
        {
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła.");

            // 1. Usuwamy wszystkie wpisy z tabeli logów
            _context.AuditLogs.RemoveRange(_context.AuditLogs);
            await _context.SaveChangesAsync();

            // 2. Resetujemy licznik Auto-Increment dla SQLite, żeby nowe ID znowu startowało od 1
            await _context.Database.ExecuteSqlRawAsync("DELETE FROM sqlite_sequence WHERE name='AuditLogs'");

            // 3. Automatycznie zdejmujemy kwarantannę (jeśli była aktywna)
            _appState.IsQuarantineActive = false;
            _appState.QuarantineReason = string.Empty;

            return Ok(new { message = "Baza danych wyczyszczona! Licznik ID zresetowany. Gotowe do nowej prezentacji." });
        }

        [HttpPost("simulate-chain-break/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> SimulateChainBreak(int id)
        {
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła.");

            var logToBreak = await _context.AuditLogs.FindAsync(id);
            if (logToBreak == null) return NotFound($"Brak transakcji o ID {id}");

            // Haker niszczy powiązanie z poprzednim blokiem
            logToBreak.PreviousHash = "HACKED_CHAIN_0000000000000000000";
            await _context.SaveChangesAsync();

            return Ok(new { message = "Łańcuch chronologiczny został zerwany! Watchdog zaraz to wykryje." });
        }

        [HttpPost("seed")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> SeedDatabase()
        {
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła.");

            var receivers = new[] { "Jan Kowalski", "Sklep Elektroniczny", "Anna Nowak", "Opłata za prąd", "Księgarnia Naukowa", "Politechnika Śląska", "Urząd Skarbowy", "Hurtownia IT" };
            var random = new Random();

            for (int i = 0; i < 10; i++)
            {
                var receiver = receivers[random.Next(receivers.Length)];
                var amount = Math.Round((decimal)(random.NextDouble() * 2500 + 50), 2);

                var lastLog = await _context.AuditLogs.OrderByDescending(l => l.Id).FirstOrDefaultAsync();
                string previousHash = lastLog?.Hash ?? new string('0', 64);

                var newLog = new AuditLog
                {
                    Sender = User.Identity?.Name ?? "Admin",
                    Receiver = receiver,
                    Amount = amount,
                    Timestamp = DateTime.UtcNow,
                    IpAddress = "127.0.0.1",
                    UserAgent = "Auto-Seeder/1.0",
                    PreviousHash = previousHash
                };

                newLog.Hash = _cryptoService.CalculateHashForLog(newLog);
                _context.AuditLogs.Add(newLog);
                await _context.SaveChangesAsync();
            }

            return Ok(new { message = "Wygenerowano 10 losowych przelewów testowych." });
        }
    }
}
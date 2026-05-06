using MerkleAudit.Api.Data;
using MerkleAudit.Api.Models;
using MerkleAudit.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Security.Cryptography;

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

        public AuditController(AppDbContext context, MerkleTreeBuilder treeBuilder, CryptoService cryptoService)
        {
            _context = context;
            _treeBuilder = treeBuilder;
            _cryptoService = cryptoService;
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

        // 1. Wgląd do historii przelewów - TYLKO DLA ADMINA
        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetAllLogs()
        {
            // BLOKADA SESJI
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła lub baza została zresetowana.");

            var logs = await _context.AuditLogs.ToListAsync();
            return Ok(logs);
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
        [Authorize(Roles = "Admin")]
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
        [HttpPost("simulate-attack")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> SimulateAttack()
        {
            // BLOKADA SESJI
            if (!await IsSessionValid()) return Unauthorized("Sesja wygasła.");

            var logToHack = await _context.AuditLogs.FirstOrDefaultAsync();

            if (logToHack == null)
            {
                return NotFound("Brak transakcji w bazie do zhakowania!");
            }

            logToHack.Amount += 999999;
            await _context.SaveChangesAsync();

            return Ok(new { message = $"Włamanie udane! Kwota przelewu ID {logToHack.Id} została zmanipulowana. Watchdog powinien wkrótce zareagować." });
        }
    }
}
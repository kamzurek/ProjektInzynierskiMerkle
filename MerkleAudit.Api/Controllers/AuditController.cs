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

        // 1. Wgląd do historii przelewów - TYLKO DLA ADMINA
        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetAllLogs()
        {
            var logs = await _context.AuditLogs.ToListAsync();
            return Ok(logs);
        }

        // 2. Dodanie starego typu logu ręcznie - TYLKO DLA ADMINA
        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AddLog([FromBody] AuditLog newLog)
        {
            // 1. Zapisujemy goły wpis do bazy, żeby SQLite nadał mu prawdziwe ID (np. 1, 2, 3)
            _context.AuditLogs.Add(newLog);
            await _context.SaveChangesAsync();

            // 2. Teraz nasz newLog ma już poprawne ID. Liczymy z niego Hash!
            newLog.Hash = _cryptoService.CalculateHashForLog(newLog);

            // 3. Aktualizujemy wpis w bazie o nowo wyliczoną "plombę"
            await _context.SaveChangesAsync();

            return Ok(newLog);
        }

        // 3. Pobieranie dowodów kryptograficznych - TYLKO DLA ADMINA
        [HttpGet("root")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetMerkleRoot()
        {
            var logs = await _context.AuditLogs.ToListAsync();
            var root = _treeBuilder.BuildRoot(logs);

            if (string.IsNullOrEmpty(root))
            {
                return Ok(new { message = "Drzewo jest puste - brak logów" });
            }

            // Serwer bierze swój tajny klucz i składa cyfrowy podpis pod Rootem
            var digitalSignature = _cryptoService.SignData(root);

            // Pobieramy klucz publiczny, żeby udostępnić go światu do weryfikacji podpisu
            var publicKey = _cryptoService.GetPublicKey();

            return Ok(new
            {
                currentRoot = root,
                serverSignature = digitalSignature, // Kryptograficzny dowód autentyczności!
                publicKey = publicKey               // Klucz do sprawdzenia dowodu
            });
        }

        // 4. NOWY PRZELEW: Dostępny DLA KAŻDEGO zalogowanego (Admin oraz User)
        [HttpPost("transfer")]
        [Authorize]
        public async Task<IActionResult> MakeTransfer(TransferDto request)
        {
            // 1. Wyciągamy tożsamość prosto z tokenu JWT!
            var loggedInUser = User.Identity?.Name;

            if (string.IsNullOrEmpty(loggedInUser))
            {
                return Unauthorized("Brak informacji o tożsamości w tokenie.");
            }

            // 2. Tworzymy nowy log, ignorując pole Sender wysłane w JSON
            var newLog = new AuditLog
            {
                Sender = loggedInUser, // <--- Wpisujemy nazwę zalogowanego użytkownika!
                Receiver = request.Receiver,
                Amount = request.Amount,
                Hash = "pending..."
            };

            // 3. Zapisujemy goły wpis do bazy (nadanie ID)
            _context.AuditLogs.Add(newLog);
            await _context.SaveChangesAsync();

            // 4. Obliczamy prawidłowy hash naszym autorskim serwisem
            newLog.Hash = _cryptoService.CalculateHashForLog(newLog);

            // 5. Aktualizujemy w bazie z prawidłową plombą
            await _context.SaveChangesAsync();

            return Ok(newLog);
        }

        // 5. SYMULACJA ATAKU (Backdoor z poprzedniego etapu) - TYLKO DLA ADMINA
        [HttpPost("simulate-attack")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> SimulateAttack()
        {
            // 1. Pobieramy najstarszy log z bazy
            var logToHack = await _context.AuditLogs.FirstOrDefaultAsync();

            if (logToHack == null)
            {
                return NotFound("Brak transakcji w bazie do zhakowania!");
            }

            // 2. SYMULACJA ATAKU: Zmieniamy kwotę na absurdalnie wielką.
            // Zauważ, że celowo NIE przeliczamy na nowo hasza!
            logToHack.Amount += 999999;

            // 3. Zapisujemy zepsuty rekord do bazy
            await _context.SaveChangesAsync();

            return Ok(new { message = $"Włamanie udane! Kwota przelewu ID {logToHack.Id} została zmanipulowana. Watchdog powinien wkrótce zareagować." });
        }
    }
}
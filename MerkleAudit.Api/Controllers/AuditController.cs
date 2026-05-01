using MerkleAudit.Api.Data;
using MerkleAudit.Api.Models;
using MerkleAudit.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace MerkleAudit.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
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

        // 1. Zwykłe pobranie historii przelewów
        [HttpGet]
        public async Task<IActionResult> GetAllLogs()
        {
            var logs = await _context.AuditLogs.ToListAsync();
            return Ok(logs);
        }

        // 2. Dodanie nowego przelewu
        [HttpPost]
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

        // 3. WERSJA INŻYNIERSKA: Obliczanie Roota + Podpis Cyfrowy RSA
        [HttpGet("root")]
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
    }
}
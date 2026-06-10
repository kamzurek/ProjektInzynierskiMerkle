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


using System.Collections.Generic;
using MerkleAudit.Api.Models;

namespace MerkleAudit.Api.Services
{
    // Mała klasa pomocnicza, którą wyślemy do Reacta. 
    // Mówi ona: "Weź ten Hash i doklej go z Lewej (lub z Prawej) strony swojego Hasha".
    public class MerkleProofNode
    {
        public string Hash { get; set; } = string.Empty;
        public string Direction { get; set; } = string.Empty; // "Left" lub "Right"
    }

    public class MerkleTreeBuilder
    {
        private readonly CryptoService _cryptoService;

        // "Wstrzykujemy" nasz serwis kryptograficzny, żeby móc z niego korzystać w tej klasie
        public MerkleTreeBuilder(CryptoService cryptoService)
        {
            _cryptoService = cryptoService;
        }

        // 1. GŁÓWNA METODA (Twoja dotychczasowa)
        public string BuildRoot(List<AuditLog> logs)
        {
            if (logs == null || logs.Count == 0)
                return null;

            List<string> currentLevel = new List<string>();
            foreach (var log in logs)
            {
                string logHash = string.IsNullOrEmpty(log.Hash) ? _cryptoService.CalculateHashForLog(log) : log.Hash;
                currentLevel.Add(logHash);
            }

            while (currentLevel.Count > 1)
            {
                List<string> nextLevel = new List<string>();
                for (int i = 0; i < currentLevel.Count; i += 2)
                {
                    string leftHash = currentLevel[i];
                    string rightHash = (i + 1 < currentLevel.Count) 
                                       ? currentLevel[i + 1] 
                                       : leftHash;
                    string combinedHash = _cryptoService.CombineAndHash(leftHash, rightHash);
                    nextLevel.Add(combinedHash);
                }
                currentLevel = nextLevel;
            }

            return currentLevel[0];
        }

        // 2. NOWA METODA INŻYNIERSKA: Generowanie Dowodu Inkluzji (Merkle Proof)
        public List<MerkleProofNode> GetProof(List<AuditLog> logs, string targetHash)
        {
            if (logs == null || logs.Count == 0) return null;

            List<string> currentLevel = new List<string>();
            int targetIndex = -1;

            // Najpierw ładujemy najniższy poziom (wszystkie hasze) i szukamy, gdzie jest nasz przelew
            for (int i = 0; i < logs.Count; i++)
            {
                string logHash = string.IsNullOrEmpty(logs[i].Hash) ? _cryptoService.CalculateHashForLog(logs[i]) : logs[i].Hash;
                currentLevel.Add(logHash);

                if (logHash == targetHash)
                {
                    targetIndex = i; // Znaleźliśmy nasz przelew, zapisujemy jego pozycję!
                }
            }

            if (targetIndex == -1) return null; // Błąd: Przelew nie istnieje w bazie

            List<MerkleProofNode> proof = new List<MerkleProofNode>();

            // Wspinamy się po drzewie w górę (identycznie jak przy budowaniu Roota)
            while (currentLevel.Count > 1)
            {
                List<string> nextLevel = new List<string>();

                // Sprawdzamy czy nasz target na tym poziomie jest po parzystej (Lewa) czy nieparzystej (Prawa) stronie
                bool isRightNode = targetIndex % 2 != 0;

                // Jeśli jesteśmy z prawej, nasz "brat" do pary jest z lewej (targetIndex - 1) i na odwrót
                int siblingIndex = isRightNode ? targetIndex - 1 : targetIndex + 1;

                // Uwzględniamy logikę nieparzystej liczby elementów z Twojego BuildRoot (duplikacja)
                if (siblingIndex >= currentLevel.Count)
                {
                    siblingIndex = targetIndex;
                }

                // Dodajemy brata do dowodu!
                proof.Add(new MerkleProofNode
                {
                    Hash = currentLevel[siblingIndex],
                    Direction = isRightNode ? "Left" : "Right" // Mówimy klientowi, z której strony ma go dokleić
                });

                // Budujemy wyższy poziom drzewa dla kolejnej iteracji pętli
                for (int i = 0; i < currentLevel.Count; i += 2)
                {
                    string leftHash = currentLevel[i];
                    string rightHash = (i + 1 < currentLevel.Count) ? currentLevel[i + 1] : leftHash;
                    nextLevel.Add(_cryptoService.CombineAndHash(leftHash, rightHash));
                }

                currentLevel = nextLevel;
                // Na wyższym poziomie nasz target ma już o połowę mniejszy indeks
                targetIndex /= 2;
            }

            return proof;
        }
    }
}
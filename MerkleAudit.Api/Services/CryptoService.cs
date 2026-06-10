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


using System;
using System.Security.Cryptography;
using System.Text;
using MerkleAudit.Api.Models;

namespace MerkleAudit.Api.Services
{
    public class CryptoService
    {
        private readonly RSA _rsa;
        // Ścieżka do pliku, w którym ukryjemy klucz prywatny serwera
        private readonly string _keyFolder = "Keys";
        private readonly string _keyFileName = "server_private.xml";

        public CryptoService()
        {
            _rsa = RSA.Create(2048);
            InitializeKeys();
        }

        private void InitializeKeys()
        {
            // 1. Tworzymy folder Keys, jeśli nie istnieje
            if (!Directory.Exists(_keyFolder))
            {
                Directory.CreateDirectory(_keyFolder);
            }

            string fullPath = Path.Combine(_keyFolder, _keyFileName);

            // 2. Jeśli plik klucza już istnieje - wczytujemy go
            if (File.Exists(fullPath))
            {
                string xmlKey = File.ReadAllText(fullPath);
                _rsa.FromXmlString(xmlKey);
                Console.WriteLine(">>> [Crypto] Wczytano istniejący klucz serwera z pliku.");
            }
            // 3. Jeśli nie ma klucza - generujemy i zapisujemy
            else
            {
                string xmlKey = _rsa.ToXmlString(true); // 'true' oznacza eksport z kluczem prywatnym
                File.WriteAllText(fullPath, xmlKey);
                Console.WriteLine(">>> [Crypto] Wygenerowano i zapisano nowy klucz serwera.");
            }
        }

        // --- Pozostałe metody pozostają bez zmian ---

        public string CalculateHashForLog(AuditLog log)
        {
            string amountFormatted = log.Amount.ToString
                ("0.00", System.Globalization.CultureInfo.InvariantCulture);
            string dateFormatted = log.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss");
            string rawData = $"{log.Id}{log.Sender}{log.Receiver}" +
                 $"{amountFormatted}{dateFormatted}" +
                 $"{log.IpAddress}{log.UserAgent}{log.PreviousHash}";

            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {

                byte[] hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(rawData));
                System.Text.StringBuilder builder = new System.Text.StringBuilder();
                foreach (var b in hashBytes)
                {
                    builder.Append(b.ToString("x2"));
                }
                return builder.ToString();
            }
        }

        public string CombineAndHash(string leftHash, string rightHash)
        {
            string combinedData = leftHash + rightHash;
            byte[] bytes = Encoding.UTF8.GetBytes(combinedData);

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(bytes);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }

        public string SignData(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] signatureBytes = _rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signatureBytes);
        }

        public bool VerifySignature(string data, string signatureBase64)
        {
            try
            {
                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                byte[] signatureBytes = Convert.FromBase64String(signatureBase64);
                return _rsa.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch { return false; }
        }

        public string GetPublicKey()
        {
            return _rsa.ToXmlString(false);
        }
    }
}
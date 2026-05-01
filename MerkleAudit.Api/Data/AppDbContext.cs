using MerkleAudit.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace MerkleAudit.Api.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        // Ta linijka mówi systemowi: "Chcę mieć w bazie tabelę o nazwie 'AuditLogs', 
        // która będzie wyglądać dokładnie tak, jak zaplanowaliśmy w klasie AuditLog"
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<User> Users { get; set; }
    }
}

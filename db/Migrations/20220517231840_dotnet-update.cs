using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace DataDonation.Migrations {
  public partial class dotnetupdate : Migration {
    protected override void Up(MigrationBuilder migrationBuilder) {
      migrationBuilder.AlterColumn<DateTime>(
          name: "date", table: "DataDonationEntries", type: "datetime(6)",
          nullable: false, oldClrType: typeof(DateTime), oldType: "datetime");

      migrationBuilder
          .AlterColumn<string>(name: "data", table: "DataDonationEntries",
                               type: "longtext", nullable: true,
                               oldClrType: typeof(string), oldType: "text",
                               oldNullable: true)
          .Annotation("MySql:CharSet", "utf8mb4")
          .OldAnnotation("MySql:CharSet", "utf8mb4");

      migrationBuilder.AlterColumn<Guid>(
          name: "Id", table: "DataDonationEntries", type: "binary(16)",
          nullable: false, oldClrType: typeof(byte[]),
          oldType: "varbinary(16)");
    }

    protected override void Down(MigrationBuilder migrationBuilder) {
      migrationBuilder.AlterColumn<DateTime>(
          name: "date", table: "DataDonationEntries", type: "datetime",
          nullable: false, oldClrType: typeof(DateTime),
          oldType: "datetime(6)");

      migrationBuilder
          .AlterColumn<string>(name: "data", table: "DataDonationEntries",
                               type: "text", nullable: true,
                               oldClrType: typeof(string), oldType: "longtext",
                               oldNullable: true)
          .Annotation("MySql:CharSet", "utf8mb4")
          .OldAnnotation("MySql:CharSet", "utf8mb4");

      migrationBuilder.AlterColumn<byte[]>(
          name: "Id", table: "DataDonationEntries", type: "varbinary(16)",
          nullable: false, oldClrType: typeof(Guid), oldType: "binary(16)");
    }
  }
}

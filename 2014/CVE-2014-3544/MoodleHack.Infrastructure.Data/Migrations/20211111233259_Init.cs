using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace MoodleHack.Infrastructure.Data.Migrations
{
    public partial class Init : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Requests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Ip = table.Column<string>(type: "text", nullable: true),
                    Request = table.Column<string>(type: "text", nullable: true),
                    Success = table.Column<bool>(type: "boolean", nullable: false),
                    Created = table.Column<DateTime>(type: "timestamp without time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Requests", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Role = table.Column<string>(type: "text", nullable: true),
                    Cookie = table.Column<string>(type: "text", nullable: true),
                    Fio = table.Column<string>(type: "text", nullable: true),
                    Created = table.Column<DateTime>(type: "timestamp without time zone", nullable: false),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Requests_Created",
                table: "Requests",
                column: "Created");

            migrationBuilder.CreateIndex(
                name: "IX_Requests_Ip",
                table: "Requests",
                column: "Ip");

            migrationBuilder.CreateIndex(
                name: "IX_Requests_Request",
                table: "Requests",
                column: "Request");

            migrationBuilder.CreateIndex(
                name: "IX_Requests_Success",
                table: "Requests",
                column: "Success");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Cookie",
                table: "Users",
                column: "Cookie");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Created",
                table: "Users",
                column: "Created");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Fio",
                table: "Users",
                column: "Fio");

            migrationBuilder.CreateIndex(
                name: "IX_Users_IsActive",
                table: "Users",
                column: "IsActive");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Role",
                table: "Users",
                column: "Role");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Requests");

            migrationBuilder.DropTable(
                name: "Users");
        }
    }
}

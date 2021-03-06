using InterviewerAPI.DbModels;
using InterviewerAPI.Helpers;
using InterviewerAPI.Interfaces.Helpers;
using InterviewerAPI.Interfaces.Repositories;
using InterviewerAPI.Repositories;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

#region Predefined variables

string dbConnectionString = builder?.Configuration["MSSQL:ConnectionString"];
string secretKey = builder.Configuration["JwtToken:SecretKey"];
string issuer = builder?.Configuration["JwtToken:Issuer"];
string audience = builder?.Configuration["JwtToken:Audience"];
int accessTokenExpirationTimeInMinutes = int.Parse(builder?.Configuration["JwtToken:AccessTokenExpirationTimeInMinutes"]);
int refreshTokenExpirationTimeInDays = int.Parse(builder?.Configuration["JwtToken:RefreshTokenExpirationTimeInDays"]);
string possiblesCharsForSaltGenerator = builder?.Configuration["Security:PossiblesCharsForSaltGenerator"];

#endregion

#region Builder section

builder.Services.AddControllers();
builder.Services.AddDbContext<InterviewerAuthDbContext>(options => options.UseSqlServer(dbConnectionString));
builder.Services.AddEndpointsApiExplorer();

#region Repositories injection

builder.Services.AddTransient<IAuthRepository, AuthRepository>((sp) =>
{
    return new AuthRepository(refreshTokenExpirationTimeInDays,
        sp.GetService<InterviewerAuthDbContext>(), sp.GetService<IAuthHelper>());
});

builder.Services.AddTransient<IRegisterRepository, RegisterRepository>((sp) =>
{
    return new RegisterRepository(sp.GetService<InterviewerAuthDbContext>(), sp.GetService<IAuthHelper>());
});

#endregion

#region Helpers injection

builder.Services.AddTransient<IAuthHelper>((sp) => 
{
    return new AuthHelper(secretKey, issuer, audience, accessTokenExpirationTimeInMinutes);
});

#endregion

builder.Services.AddSwaggerGen();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey))
        };
    });

#endregion

#region App section

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();

#endregion
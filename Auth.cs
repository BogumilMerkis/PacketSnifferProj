using System;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;


public static class Auth
{
    public static bool Validate(HttpContext ctx)
    {
        var auth = ctx.Request.Headers["Authorization"].FirstOrDefault();
        if (auth == null || !auth.StartsWith("Basic "))
            return false;


        var encoded = auth["Basic ".Length..];
        var creds = Encoding.UTF8.GetString(Convert.FromBase64String(encoded))
        .Split(':', 2);


        if (creds.Length != 2) return false;


        var user = creds[0];
        var pass = creds[1];


        var envUser = Environment.GetEnvironmentVariable("MASTER_USER");
        var envHash = Environment.GetEnvironmentVariable("MASTER_PASS_HASH");


        if (envUser == null || envHash == null) return false;
        if (user != envUser) return false;


        return VerifyPassword(pass, envHash);
    }


    static bool VerifyPassword(string password, string stored)
    {
        var parts = stored.Split(':');
        var salt = Convert.FromBase64String(parts[0]);
        var hash = Convert.FromBase64String(parts[1]);


        var test = KeyDerivation.Pbkdf2(
        password,
        salt,
        KeyDerivationPrf.HMACSHA256,
        iterationCount: 100_000,
        numBytesRequested: 32);


        return CryptographicOperations.FixedTimeEquals(test, hash);
    }
}
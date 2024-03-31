using System.Text.RegularExpressions;

namespace JWTAuthTemplate.Services;

public class ValidPassword
{
    public enum Strength { Low = 1, Medium, High};
 
    public static Strength PasswordStrength(string password)
    {
        int score = 0;
        Dictionary<string, int> patterns = new Dictionary<string, int> { { @"\d", 5 }, //включает цифры
                                                                         { @"[a-zA-Z]", 10 }, //буквы
                                                                         { @"[!,@,#,\$,%,\^,&,\*,?,_,~]", 15 } }; //символы
        if (password.Length > 6)
            foreach (var pattern in patterns)
                score += Regex.Matches(password, pattern.Key).Count * pattern.Value;
 
        Strength result;
        switch (score / 50)
        {
            case 0: result = Strength.Low; break;
            case 1: result = Strength.Medium; break;
            case 2: result = Strength.High; break;
            default: result = Strength.High; break;
        }
        return result;
    }
}
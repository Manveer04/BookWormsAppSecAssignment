using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

public class CustomValidationAttribute : ValidationAttribute
{
    private readonly string _propertyName;
    private readonly int _minLength;
    private readonly string _pattern;
    private readonly string _errorMessage;

    public CustomValidationAttribute(string propertyName, int minLength = 0, string pattern = null, string errorMessage = null)
    {
        _propertyName = propertyName;
        _minLength = minLength;
        _pattern = pattern;
        _errorMessage = errorMessage;
    }

    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        if (value == null || (value is string str && str.Length < _minLength))
        {
            return new ValidationResult(_errorMessage ?? $"{_propertyName} must be at least {_minLength} characters long.");
        }

        if (!string.IsNullOrEmpty(_pattern) && value is string strValue && !Regex.IsMatch(strValue, _pattern))
        {
            return new ValidationResult(_errorMessage ?? $"{_propertyName} is not in the correct format.");
        }

        if (value is string password)
        {
            if (!Regex.IsMatch(password, @"[A-Z]"))
            {
                return new ValidationResult($"{_propertyName} must contain at least one uppercase letter.");
            }
            if (!Regex.IsMatch(password, @"[a-z]"))
            {
                return new ValidationResult($"{_propertyName} must contain at least one lowercase letter.");
            }
            if (!Regex.IsMatch(password, @"\d"))
            {
                return new ValidationResult($"{_propertyName} must contain at least one digit.");
            }
            if (!Regex.IsMatch(password, @"[\W_]"))
            {
                return new ValidationResult($"{_propertyName} must contain at least one special character.");
            }
        }

        return ValidationResult.Success;
    }
}

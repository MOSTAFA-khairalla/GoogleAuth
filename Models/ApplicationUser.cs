namespace GoogleAuth.Models
{
    public class ApplicationUser
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }

        // For local authentication
        public string? PasswordHash { get; set; }

        // For Google authentication
        public string? GoogleId { get; set; }

        // Optional profile data
        public string? ProfilePictureUrl { get; set; }
    }
}

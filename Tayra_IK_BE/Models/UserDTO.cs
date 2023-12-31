using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Xml.Schema;
using Tayra_IK.Enums;

namespace Tayra_IK.Models
{

    // Worker model
    public class Worker
    {
        [Key]
        [MaxLength(11)] // Assuming TC_Identity has 11 digits
        public string TC_Identity { get; set; }

        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string EmployeeRole { get; set; }

        // Foreign key for department
        public int? DepartmentId { get; set; }
        public Department Department { get; set; }
    }

    // Department model
    public class Department
    {
        public int DepartmentId { get; set; }
        public string Name { get; set; }

        // Collection navigation properties
        public ICollection<Worker> Workers { get; set; }
        public ICollection<DepartmentManager> Managers { get; set; }
        public ICollection<DepartmentChef> Chefs { get; set; }
    }
    // DepartmentManager model
    public class DepartmentManager
    {
        public int DepartmentManagerId { get; set; }
        public int DepartmentId { get; set; }
        public int ManagerId { get; set; }

        // Navigation properties
        public Department Department { get; set; }
        public Worker Manager { get; set; }
    }

    // DepartmentChef model
    public class DepartmentChef
    {
        public int DepartmentChefId { get; set; }
        public int DepartmentId { get; set; }
        public int ChefId { get; set; }

        // Navigation properties
        public Department Department { get; set; }
        public Worker Chef { get; set; }
    }





    public class LoginModel
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }



}
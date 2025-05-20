variable "rds_password" {
  description = "RDS admin password"
  type        = string
  sensitive   = true

  validation {
    condition = (
      length(var.rds_password) >= 8 &&
      can(regex("^[\\x21-\\x7E]+$", var.rds_password)) &&
      !contains(split("", var.rds_password), "/") &&
      !contains(split("", var.rds_password), "@") &&
      !contains(split("", var.rds_password), "\"") &&
      !contains(split("", var.rds_password), " ")
    )

    error_message = "RDS password must be at least 8 characters long, contain only printable ASCII characters, and must not include '/', '@', '\"', or spaces."
  }
}

# Customer database entities

SeaORM entity models for the customer application's database boundary. Queries
must remain tenant-scoped and fail closed. Review generated schema changes and
keep authorization logic in handwritten service code rather than generated
entity files.

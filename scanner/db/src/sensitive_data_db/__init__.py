"""The databases-anywhere runner: sampled, read-only reads of any database, findings only.

It runs as a container in the customer's network. Each database is named by a
connection string (an environment variable or a mounted file); the user it
connects as is checked first and refused if it can write; the tables or
collections are sampled; and the findings document goes to the same sinks as
every other runner (`sensitive_data_core.push`). See docs/DATABASES.md.
"""

__version__ = "0.4.1"

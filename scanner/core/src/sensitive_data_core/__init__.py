"""The cloud-neutral core of the sensitive data scanner: findings only, never values.

The spec and detection (`engine`, `detect`), the findings contract
(`findings`), budgets and sampling (`adapter`, `rules`), the coverage summary
(`coverage`), the findings push interface (`push`), the readers every source
shares (`scan`, including the sampled SQL pass `scan.sql`), and the no-values
rule in code (`safety`). Nothing here names a cloud; each platform's package
(`sensitive_data_scanner` for AWS) plugs its stores in through `adapter.Adapter`.
"""

__version__ = "0.4.1"

"""The Azure scanner of the sensitive data scanner: findings only, never values.

A Container Apps job with a system-assigned managed identity runs it in the
customer's own tenant. It discovers the data stores of every subscription
under a management group (Azure Resource Graph), reads them read-only with the
identity's Reader and data-reader roles, and pushes findings only. Every store
it cannot read is in the run summary with a reason. Detection, the findings
contract, budgets, sampling and the readers are the core's
(`sensitive_data_core`); Azure's SDKs are imported here and nowhere else.
"""

__version__ = "0.6.0"
